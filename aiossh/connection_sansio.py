import asyncio
import functools
import logging
import operator
import signal
import struct
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Optional

import aiodrive

from .algorithms import AlgorithmSelection, AlgorithmSets
from .encryption.base import Encryption
from .error import (
  IntegrityVerificationError,
  ProtocolError,
  ProtocolVersionNotSupportedError,
)
from .ident_string import IdentString
from .integrity.base import IntegrityVerification
from .key_exchange.resolve import resolve_key_exchange
from .messages.base import EncodableMessage
from .messages.core import DisconnectMessage, DisconnectReason
from .messages.kex_init import KexInitMessage
from .packet import encode_packet
from .public.base import PrivateKey
from .public.rsa import RSAPrivateKey


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class DataEvent:
  chunk: bytes

@dataclass(slots=True)
class InitializationEvent:
  pass

type Event = DataEvent | InitializationEvent


@dataclass(slots=True)
class SansIOConnectionSettings:
  host_keys: list[PrivateKey]
  software_version: str
  supported_algorithms: AlgorithmSets = field(default_factory=AlgorithmSets)


@dataclass(slots=True)
class TerminatedState:
  pass

@dataclass(slots=True)
class WaitingForIdentStringState:
  pass

type State = TerminatedState | WaitingForIdentStringState


@dataclass(slots=True)
class SansIOConnection:
  settings: SansIOConnectionSettings

  # _state: State = field(default_factory=WaitingForIdentStringState)
  _terminated: bool = field(default=False, init=False)

  _client_ident_string: Optional[IdentString] = field(default=None, init=False)
  _server_ident_string: IdentString = field(init=False)
  _server_kex_init_payload: bytes = field(init=False)

  _sequence_number_in: int = field(default=0, init=False)
  _sequence_number_out: int = field(default=0, init=False)
  # _session_id: Optional[bytes] = field(init=False)

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

  def _receive(self, length: int, /):
    if len(self._receive_buffer) < length:
      return None

    chunk = self._receive_buffer[:length]
    self._receive_buffer = self._receive_buffer[length:]

    return chunk

  def _send(self, chunk: bytes, /):
    self._send_buffer += chunk

  def _send_message(self, message: EncodableMessage):
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

      client_ident_string_terminated = self._receive_buffer[:termination_index]
      self._receive_buffer = self._receive_buffer[(termination_index + 2):]

      try:
        self._client_ident_string = IdentString.decode(client_ident_string_terminated[:-2])
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
      self._send_kex_init(is_first=True)

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

      self._receive_message(payload, sequence_number)

  def _receive_message(self, payload: bytes, sequence_number: int):
    message_id = payload[0]
    LOGGER.debug(f'Received message id {message_id} (sequence number {sequence_number})')

    match message_id:
      case KexInitMessage.id:
        message = KexInitMessage.decode_payload(payload)

        # Negotiate algorithms

        algorithm_selection = self.settings.supported_algorithms.negotiate(message)
        host_key = next(key for key in self.settings.host_keys if algorithm_selection.server_host_key_algorithm in key.algorithms())


        # Ignore next packet if the preferred algorithms do not match

        if message.first_kex_packet_follows and (
          (algorithm_selection.kex_algorithm != message.kex_algorithms[0])
          or (algorithm_selection.server_host_key_algorithm != message.server_host_key_algorithms[0])
          or (algorithm_selection.encryption_algorithm_client_to_server != message.encryption_algorithms_client_to_server[0])
          or (algorithm_selection.encryption_algorithm_server_to_client != message.encryption_algorithms_server_to_client[0])
          or (algorithm_selection.mac_algorithm_client_to_server != message.mac_algorithms_client_to_server[0])
          or (algorithm_selection.mac_algorithm_server_to_client != message.mac_algorithms_server_to_client[0])
        ):
          # TODO: Skip next packet
          raise NotImplementedError


        # Run key exchange

        key_exchange = resolve_key_exchange(algorithm_selection.kex_algorithm)

        print(key_exchange)


  def _send_kex_init(self, is_first: bool):
    # supported_algorithms.server_host_key_algorithms &= functools.reduce(operator.or_, (key.algorithms() for key in self.server.host_keys))

    usable_server_host_key_algorithms = functools.reduce(operator.or_, (key.algorithms() for key in self.settings.host_keys), set())
    server_host_key_algorithms = [
      algorithm for algorithm in self.settings.supported_algorithms.server_host_key_algorithms if algorithm in usable_server_host_key_algorithms
    ]

    self._server_kex_init_payload = self._send_message(
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
  async def tcp_handler(tcp_connection: aiodrive.Connection):
    LOGGER.debug(f'Incoming connection from {tcp_connection.client_name} to {tcp_connection.server_name}')

    conn = SansIOConnection(
      settings=SansIOConnectionSettings(
        host_keys=get_host_keys(),
        software_version='aiossh_0.0.0',
      ),
    )

    while True:
      for event in conn.events():
        match event:
          case DataEvent(chunk):
            tcp_connection.writer.write(chunk)
            await tcp_connection.writer.drain()
          case _:
            print('Event:', event)


      chunk = await tcp_connection.reader.read(65_536)
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
