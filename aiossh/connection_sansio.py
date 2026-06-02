import logging
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Optional

from .algorithms import AlgorithmSelection
from .encryption.base import Encryption
from .error import ProtocolError, ProtocolVersionNotSupportedError, UnreachableError
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


@dataclass(slots=True)
class SansIOConnection:
  settings: SansIOConnectionSettings

  _state: State = field(default_factory=WaitingForIdentStringState)

  _client_ident_string: IdentString = field(init=False)
  _server_ident_string: IdentString = field(init=False)

  _sequence_number_in: int = field(default=0, init=False)
  _sequence_number_out: int = field(default=0, init=False)
  _session_id: Optional[bytes] = None

  _algorithm_selection: Optional[AlgorithmSelection] = field(default=None, init=False)
  _encryption_in: Optional[Encryption] = field(default=None, init=False)
  _encryption_out: Optional[Encryption] = field(default=None, init=False)
  _host_key: Optional[PrivateKey] = field(default=None, init=False)
  _integrity_verification_in: Optional[IntegrityVerification] = field(default=None, init=False)
  _integrity_verification_out: Optional[IntegrityVerification] = field(default=None, init=False)

  _receive_buffer: bytes = field(default_factory=bytes)
  _send_buffer: bytes = field(default_factory=bytes)
  _events: deque[Event] = field(default_factory=deque)

  def __post_init__(self):
    self._server_ident_string = IdentString(
      comment=None,
      software_version=self.settings.software_version,
    )

    self._send(bytes(self._server_ident_string) + b'\r\n')

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
    if isinstance(self._state, TerminatedState):
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

    match self._state:
      case TerminatedState():
        raise RuntimeError('Connection is terminated')

      # See: RFC 4253 Section 4.2
      case WaitingForIdentStringState():
        max_terminated_ident_string_length = 255

        try:
          termination_index = self._receive_buffer[:max_terminated_ident_string_length].index(b'\r\n')
        except ValueError:
          if len(self._receive_buffer) >= max_terminated_ident_string_length:
            raise ProtocolError

          return

        self._receive_buffer = self._receive_buffer[(termination_index + 2):]
        client_ident_string_terminated = self._receive_buffer[:termination_index]

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

        LOGGER.debug(f'Client version: "{self._client_ident_string.software_version}"')

      case _:
        raise UnreachableError
