import asyncio
import logging
import signal
import struct
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Optional

import aiodrive

from .algorithms import AlgorithmSelection
from .encryption.base import Encryption
from .error import (
  IntegrityVerificationError,
  ProtocolError,
  ProtocolVersionNotSupportedError,
)
from .ident_string import IdentString
from .integrity.base import IntegrityVerification
from .messages.base import EncodableMessage
from .messages.core import DisconnectMessage, DisconnectReason
from .packet import encode_packet
from .public.base import PrivateKey


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
  software_version: str


@dataclass(slots=True)
class TerminatedState:
  pass

@dataclass(slots=True)
class WaitingForIdentStringState:
  pass

type State = TerminatedState | WaitingForIdentStringState


# class ReceivedM


@dataclass(slots=True)
class SansIOConnection:
  settings: SansIOConnectionSettings

  # _state: State = field(default_factory=WaitingForIdentStringState)
  _terminated: bool = field(default=False, init=False)

  _client_ident_string: Optional[IdentString] = field(default=None, init=False)
  _server_ident_string: IdentString = field(init=False)

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
    sized_packet = encode_packet(
      payload,
      block_size=(self._encryption_out.block_size() if self._encryption_out else None),
    )

    if self._encryption_out is not None:
      self._send(self._encryption_out.encrypt_blocks(sized_packet))
    else:
      self._send(sized_packet)

    if self._integrity_verification_out is not None:
      self._integrity_verification_out.start(self._sequence_number_out)
      self._integrity_verification_out.update(sized_packet)
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

      message_id = payload[0]
      LOGGER.debug(f'Received message id {message_id} (sequence number {sequence_number})')


async def main():
  async def tcp_handler(tcp_connection: aiodrive.Connection):
    LOGGER.debug(f'Incoming connection from {tcp_connection.client_name} to {tcp_connection.server_name}')

    conn = SansIOConnection(
      settings=SansIOConnectionSettings(
        software_version='aiossh_0.0.0',
      ),
    )

    while True:
      for event in conn.events():
        print('Event:', event)

        match event:
          case DataEvent(chunk):
            tcp_connection.writer.write(chunk)
            await tcp_connection.writer.drain()

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
