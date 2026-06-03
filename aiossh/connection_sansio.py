import asyncio
import functools
import logging
import operator
import os
import signal
import struct
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Optional

import aiodrive

from .algorithms import AlgorithmSelection, AlgorithmSets
from .encryption.base import Encryption
from .encryption.resolve import resolve_encryption
from .error import (
  IntegrityVerificationError,
  ProtocolError,
  ProtocolVersionNotSupportedError,
)
from .flow import MessageFlow, MessageStub
from .ident_string import IdentString
from .integrity.base import IntegrityVerification
from .integrity.resolve import resolve_integrity_verification
from .key_exchange.resolve import resolve_key_exchange
from .messages.base import Message
from .messages.core import (
  DisconnectMessage,
  DisconnectReason,
  ExtInfoMessage,
  NewKeysMessage,
)
from .messages.kex_init import KexInitMessage
from .packet import encode_packet
from .public.base import PrivateKey
from .public.rsa import RSAPrivateKey
from .structures.primitives import encode_mpint, encode_name_list, encode_string


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class DataEvent:
  chunk: bytes

@dataclass(slots=True)
class ExchangedKeysEvent:
  pass

type Event = DataEvent | ExchangedKeysEvent


@dataclass(slots=True)
class SansIOConnectionSettings:
  host_keys: list[PrivateKey]
  software_version: str
  supported_algorithms: AlgorithmSets = field(default_factory=AlgorithmSets)


# @dataclass(slots=True)
# class WaitingForKexInitState:
#   pass

# class RunningKeyExchangeState:
#   pass

# type State = TerminatedState | WaitingForIdentStringState


@dataclass
class SansIOConnection:
  settings: SansIOConnectionSettings

  # _state: State = field(default_factory=WaitingForIdentStringState)
  _terminated: bool = field(default=False, init=False)

  _client_ident_string: Optional[IdentString] = field(default=None, init=False)
  _server_ident_string: IdentString = field(init=False)

  _sequence_number_in: int = field(default=0, init=False)
  _sequence_number_out: int = field(default=0, init=False)
  _session_id: Optional[bytes] = field(default=None, init=False)

  # Initialized after key exchange is complete
  _transmitted_byte_count: int = field(init=False)

  _key_exchange: Optional[MessageFlow[None]] = field(default=None, init=False)

  _algorithm_selection: Optional[AlgorithmSelection] = field(default=None, init=False)
  _encryption_in: Optional[Encryption] = field(default=None, init=False)
  _encryption_out: Optional[Encryption] = field(default=None, init=False)
  _host_key: Optional[PrivateKey] = field(default=None, init=False)
  _integrity_verification_in: Optional[IntegrityVerification] = field(default=None, init=False)
  _integrity_verification_out: Optional[IntegrityVerification] = field(default=None, init=False)

  _receive_buffer: bytes = field(default_factory=bytes, init=False)
  _send_buffer: bytes = field(default_factory=bytes, init=False)
  _events: deque[Event] = field(default_factory=deque, init=False)
  _received_partial_packet: Optional[bytes] = field(default=None, init=False)

  def __post_init__(self):
    self._server_ident_string = IdentString(
      comment=None,
      software_version=self.settings.software_version,
    )

    self._send(bytes(self._server_ident_string) + b'\r\n')

  @functools.cached_property
  def _dh_groups(self):
    from .primes.well_known import groups as well_known_dh_groups
    return well_known_dh_groups

  def _receive(self, length: int, /):
    if len(self._receive_buffer) < length:
      return None

    chunk = self._receive_buffer[:length]
    self._receive_buffer = self._receive_buffer[length:]

    return chunk

  def _send(self, chunk: bytes, /):
    self._send_buffer += chunk

  def _send_message(self, message: Message):
    payload = message.encode_payload()
    packet_with_length = encode_packet(
      payload,
      block_size=(self._encryption_out.block_size() if self._encryption_out else None),
    )

    if self._encryption_out is not None:
      self._send(self._encryption_out.encrypt_blocks(packet_with_length))
    else:
      self._send(packet_with_length)

    if self._integrity_verification_out is not None:
      self._integrity_verification_out.start(self._sequence_number_out)
      self._integrity_verification_out.update(packet_with_length)
      self._send(self._integrity_verification_out.digest())

    self._sequence_number_out += 1

    # Return payload because the KexInit message payload is reused for key exchange
    return payload


  def events(self) -> Iterator[Event]:
    if self._terminated:
      raise RuntimeError('Connection is terminated')

    while True:
      if self._send_buffer:
        buffer = self._send_buffer
        self._send_buffer = b''
        yield DataEvent(buffer)
      elif self._events:
        yield self._events.popleft()
      else:
        break

  def feed(self, chunk: bytes, /):
    self._receive_buffer += chunk

    if self._terminated:
      raise RuntimeError('Connection is terminated')

    if self._client_ident_string is None:
      # See: RFC 4253 Section 4.2
      max_terminated_ident_string_length = 255

      try:
        termination_index = self._receive_buffer[:max_terminated_ident_string_length].index(b'\r\n')
      except ValueError:
        if len(self._receive_buffer) >= max_terminated_ident_string_length:
          raise ProtocolError

        return

      client_ident_string_unterminated = self._receive_buffer[:termination_index]
      self._receive_buffer = self._receive_buffer[(termination_index + 2):]

      try:
        # `client_ident_string_unterminated` already excludes CRLF.
        self._client_ident_string = IdentString.decode(client_ident_string_unterminated)
      except ProtocolVersionNotSupportedError:
        self._send_message(
          DisconnectMessage(
            reason_code=DisconnectReason.ProtocolVersionNotSupported,
            description='Protocol version not supported',
            language_tag='',
          ),
        )

        self._terminated = True
        return

      LOGGER.debug(f'Client version: "{self._client_ident_string.software_version}"')

      self._key_exchange = iter(self._run_key_exchange())
      next(self._key_exchange)

    while True:
      packet_length_size = 4
      padding_length_size = 1

      block_size_or_zero = self._encryption_in.block_size() if self._encryption_in is not None else 0
      digest_size_or_zero = self._integrity_verification_in.digest_size if self._integrity_verification_in is not None else 0


      # Read packet length (without the length itself) or first block

      if self._received_partial_packet is None:
        if self._encryption_in is not None:
          self._received_partial_packet = self._receive(self._encryption_in.block_size())
        else:
          self._received_partial_packet = self._receive(packet_length_size)

      if self._received_partial_packet is None:
        break


      # Read rest of packet
      # See: RFC 4253 Section 6

      if self._encryption_in is not None:
        partial_packet = self._encryption_in.decrypt_blocks(self._received_partial_packet)
      else:
        partial_packet = self._received_partial_packet

      packet_length_bytes = partial_packet[:packet_length_size]
      packet_length = struct.unpack('>I', packet_length_bytes)[0]

      # The packet must at least contain the padding length byte.
      if packet_length < padding_length_size:
        raise ProtocolError

      # The total packet size, with length and MAC, must not exceed 35,000 bytes.
      if packet_length_size + packet_length + digest_size_or_zero > 35_000:
        raise ProtocolError

      if self._encryption_in is not None:
        missing_block_count = (packet_length_size + packet_length - 1) // self._encryption_in.block_size()
        missing_byte_count = self._encryption_in.block_size() * missing_block_count
      else:
        missing_byte_count = packet_length

      rest = self._receive(missing_byte_count + digest_size_or_zero)

      if rest is None:
        break

      self._received_partial_packet = None

      packet_rest = rest[:missing_byte_count]
      digest = rest[missing_byte_count:]

      if self._encryption_in is not None:
        packet_with_length = partial_packet + self._encryption_in.decrypt_blocks(packet_rest)
        packet_after_length = packet_with_length[packet_length_size:]
      else:
        packet_after_length = packet_rest
        packet_with_length = partial_packet + packet_after_length

      padding_length = packet_after_length[0]
      payload_length = packet_length - padding_length - padding_length_size

      padding_alignment = max(block_size_or_zero, 8)

      # Packet size without the mac
      packet_size = packet_length_size + padding_length_size + payload_length + padding_length

      if (payload_length < 0) or (packet_size % padding_alignment) != 0 or (packet_size < max(block_size_or_zero, 16)):
        raise ProtocolError

      payload = packet_after_length[padding_length_size:(padding_length_size + payload_length)]


      # Verify integrity using MAC
      # See: RFC 4253 Section 6.4

      sequence_number = self._sequence_number_in

      if self._integrity_verification_in is not None:
        self._integrity_verification_in.start(sequence_number)
        self._integrity_verification_in.update(packet_with_length)
        produced_digest = self._integrity_verification_in.digest()

        if digest != produced_digest:
          raise IntegrityVerificationError


      # Return payload

      self._sequence_number_in += 1

      if len(payload) < 1:
        raise ProtocolError

      self._receive_message(MessageStub(payload), sequence_number)

  def _receive_message(self, message_stub: MessageStub, sequence_number: int):
    LOGGER.debug(f'Received message id {message_stub.id} (sequence number {sequence_number})')

    match message_stub.id:
      case KexInitMessage.id:
        if self._key_exchange is None:
          self._key_exchange = iter(self._run_key_exchange())
          next(self._key_exchange)

        self._key_exchange.send(message_stub)
      case _ if (message_stub.id == NewKeysMessage.id) or (30 <= message_stub.id <= 49):
        if self._key_exchange is None:
          raise ProtocolError

        try:
          self._key_exchange.send(message_stub)
        except StopIteration:
          pass
      case _:
        raise NotImplementedError(f'Unsupported message id {message_stub.id}')

  def _run_key_exchange(self) -> MessageFlow[None]:
    assert self._key_exchange is not None

    is_first = self._session_id is None

    usable_server_host_key_algorithms = functools.reduce(operator.or_, (key.algorithms() for key in self.settings.host_keys), set())
    server_host_key_algorithms = [
      algorithm for algorithm in self.settings.supported_algorithms.server_host_key_algorithms if algorithm in usable_server_host_key_algorithms
    ]

    server_kex_init_payload = self._send_message(
      KexInitMessage(
        kex_algorithms=(self.settings.supported_algorithms.kex_algorithms + (['ext-info-s'] if is_first else [])),
        server_host_key_algorithms=list(server_host_key_algorithms),
        encryption_algorithms_client_to_server=list(self.settings.supported_algorithms.encryption_algorithms_client_to_server),
        encryption_algorithms_server_to_client=list(self.settings.supported_algorithms.encryption_algorithms_server_to_client),
        mac_algorithms_client_to_server=list(self.settings.supported_algorithms.mac_algorithms_client_to_server),
        mac_algorithms_server_to_client=list(self.settings.supported_algorithms.mac_algorithms_server_to_client),
        compression_algorithms_client_to_server=list(self.settings.supported_algorithms.compression_algorithms_client_to_server),
        compression_algorithms_server_to_client=list(self.settings.supported_algorithms.compression_algorithms_server_to_client),
        languages_client_to_server=[],
        languages_server_to_client=[],
        first_kex_packet_follows=False,
      ),
    )

    client_kex_init_stub = yield
    client_kex_init = client_kex_init_stub.decode(KexInitMessage)
    client_kex_init_payload = client_kex_init_stub.payload


    # Negotiate algorithms

    algorithm_selection = self.settings.supported_algorithms.negotiate(client_kex_init)
    host_key = next(key for key in self.settings.host_keys if algorithm_selection.server_host_key_algorithm in key.algorithms())


    # Ignore next packet if the preferred algorithms do not match

    if client_kex_init.first_kex_packet_follows and (
      (algorithm_selection.kex_algorithm != client_kex_init.kex_algorithms[0])
      or (algorithm_selection.server_host_key_algorithm != client_kex_init.server_host_key_algorithms[0])
      or (algorithm_selection.encryption_algorithm_client_to_server != client_kex_init.encryption_algorithms_client_to_server[0])
      or (algorithm_selection.encryption_algorithm_server_to_client != client_kex_init.encryption_algorithms_server_to_client[0])
      or (algorithm_selection.mac_algorithm_client_to_server != client_kex_init.mac_algorithms_client_to_server[0])
      or (algorithm_selection.mac_algorithm_server_to_client != client_kex_init.mac_algorithms_server_to_client[0])
    ):
      # TODO: Skip next packet
      raise NotImplementedError


    # Run key exchange

    assert self._client_ident_string is not None

    hash_header = (
        encode_string(bytes(self._client_ident_string))
      + encode_string(bytes(self._server_ident_string))
      + encode_string(client_kex_init_payload)
      + encode_string(server_kex_init_payload)
    )

    key_exchange = resolve_key_exchange(algorithm_selection.kex_algorithm)

    exchange_hash, shared_key = yield from key_exchange.run_as_server(
      self,
      algorithm_selection=algorithm_selection,
      host_key=host_key,
      hash_header=hash_header,
    )


    # Compute key exchange output
    # See: RFC 4253 Section 7.2

    if self._session_id is None:
      self._session_id = exchange_hash

    session_id = self._session_id
    encoded_shared_secret = encode_mpint(int.from_bytes(shared_key))

    def derive_key(letter: bytes, size: int):
      key = key_exchange.hash(encoded_shared_secret + exchange_hash + letter + session_id)

      while len(key) < size:
        key += key_exchange.hash(encoded_shared_secret + exchange_hash + key)

      return key[:size]


    # Establish output algorithms

    self._send_message(NewKeysMessage())

    EncryptionOut = resolve_encryption(algorithm_selection.encryption_algorithm_server_to_client)

    self._encryption_out = EncryptionOut(
      key=derive_key(b'D', EncryptionOut.key_size()),
      iv=derive_key(b'B', EncryptionOut.block_size()),
    )

    self._integrity_verification_out = resolve_integrity_verification(algorithm_selection.mac_algorithm_server_to_client)
    self._integrity_verification_out.build(
      derive_key(b'F', self._integrity_verification_out.key_size),
    )


    # Establish input algorithms

    _ = (yield).decode(NewKeysMessage)

    EncryptionIn = resolve_encryption(algorithm_selection.encryption_algorithm_client_to_server)

    self._encryption_in = EncryptionIn(
      key=derive_key(b'C', EncryptionIn.key_size()),
      iv=derive_key(b'A', EncryptionIn.block_size()),
    )

    self._integrity_verification_in = resolve_integrity_verification(algorithm_selection.mac_algorithm_client_to_server)
    self._integrity_verification_in.build(
      derive_key(b'E', self._integrity_verification_in.key_size),
    )

    LOGGER.debug('Done with key exchange')


    # Send extensions

    if is_first:
      self._send_message(
        ExtInfoMessage(extensions={
          'server-sig-algs': encode_name_list([
            'rsa-sha2-256',
            'rsa-sha2-512',
            # TODO: List all supported algorithms
          ]),
        }),
      )

    self._events.append(ExchangedKeysEvent())
    self._key_exchange = None


def get_host_keys():
  import pickle
  from pathlib import Path

  host_keys_path = Path('tmp/keys.pkl')

  if host_keys_path.exists():
    with host_keys_path.open('rb') as file:
      host_keys: list[PrivateKey] = pickle.load(file)
  else:
    host_keys: list[PrivateKey] = [
      RSAPrivateKey.generate(),
    ]

    host_keys_path.parent.mkdir(exist_ok=True, parents=True)

    with host_keys_path.open('wb') as file:
      pickle.dump(host_keys, file)

  return host_keys


async def main():
  LOGGER.debug(f'Process id: {os.getpid()}')

  async def tcp_handler(tcp_connection: aiodrive.Connection):
    LOGGER.debug(f'Incoming connection from {tcp_connection.client_name} to {tcp_connection.server_name}')

    conn = SansIOConnection(
      settings=SansIOConnectionSettings(
        host_keys=get_host_keys(),
        software_version='aiossh_0.0.0',
      ),
    )

    while True:
      # LOGGER.debug('Enumerating events...')

      for event in conn.events():
        match event:
          case DataEvent(chunk):
            tcp_connection.writer.write(chunk)
            await tcp_connection.writer.drain()
          case _:
            print('Event:', event)


      # LOGGER.debug('Waiting for data...')
      chunk = await tcp_connection.reader.read(65_536)

      if not chunk:
        break

      conn.feed(chunk)


  try:
    with aiodrive.handle_signal([signal.SIGINT, signal.SIGTERM]):
      async with aiodrive.TCPServer.listen(
        tcp_handler,
        host=['127.0.0.1', '::1'],
        port=1302,
      ) as tcp_server:
        for binding in tcp_server.bindings:
          LOGGER.info(f'Listening on {binding}')

        await aiodrive.wait_forever()
  except aiodrive.SignalHandledException as e:
    print('\r', end='')
    LOGGER.info(f'Received {signal.Signals(e.signal).name}')


if __name__ == '__main__':
  logging.basicConfig(
    format='[%(levelname)s] %(name)s    %(message)s',
    level=logging.DEBUG,
  )

  asyncio.run(main())
