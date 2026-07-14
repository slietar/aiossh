import copy
import functools
import logging
import operator
import struct
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.constant_time import bytes_eq

from .algorithms import AlgorithmSelection, AlgorithmSets, extract
from .encryption.base import Encryption
from .encryption.resolve import resolve_encryption
from .error import (
  ConnectionTerminatedError,
  ProtocolError,
  ProtocolVersionNotSupportedError,
  UnreachableError,
)
from .events import (
  AuthWithPasswordRequestEvent,
  AuthWithPublicKeyRequestEvent,
  ChannelDataEvent,
  ChannelEofEvent,
  ChannelOpenEvent,
  DataEvent,
  Event,
  ExchangedKeysEvent,
  SessionExecEvent,
  SessionPTYOptions,
  SessionShellEvent,
  Stream,
)
from .flow import MessageFlow, MessageStub
from .ident_string import IdentString
from .integrity.base import IntegrityVerification
from .integrity.resolve import resolve_integrity_verification
from .key_exchange.resolve import resolve_key_exchange
from .messages.base import Message
from .messages.channel import (
  ChannelCloseMessage,
  ChannelDataMessage,
  ChannelEofMessage,
  ChannelOpenConfirmationMessage,
  ChannelOpenDetailsSession,
  ChannelOpenFailureMessage,
  ChannelOpenFailureReason,
  ChannelOpenMessage,
  OpenChannelMessage,
)
from .messages.channel_request import (
  ChannelFailureMessage,
  ChannelRequestDetailsEnv,
  ChannelRequestDetailsExec,
  ChannelRequestDetailsExitStatus,
  ChannelRequestDetailsPtyReq,
  ChannelRequestDetailsShell,
  ChannelRequestMessage,
  ChannelSuccessMessage,
)
from .messages.core import (
  DisconnectMessage,
  DisconnectReason,
  ExtInfoMessage,
  NewKeysMessage,
)
from .messages.key_exchange import KexInitMessage
from .messages.service import ServiceAcceptMessage, ServiceRequestMessage
from .messages.user_auth import (
  AuthenticationMethodName,
  UserAuthFailureMessage,
  UserAuthPublicKeyOk,
  UserAuthRequestDetailsPassword,
  UserAuthRequestDetailsPublicKey,
  UserAuthRequestMessage,
  UserAuthSuccessMessage,
)
from .packet import encode_packet
from .public.base import PrivateKey
from .public.resolve import SignatureAlgorithmName
from .structures.primitives import encode_mpint, encode_name_list, encode_string


LOGGER = logging.getLogger(__name__)


@dataclass(kw_only=True, slots=True)
class SansIOConnectionSettings:
  host_keys: list[PrivateKey]
  software_version: str
  supported_algorithms: AlgorithmSets = field(default_factory=AlgorithmSets)
  supported_auth_methods: list[AuthenticationMethodName]


@dataclass(kw_only=True, slots=True)
class Channel:
  # True if we have received a request and are waiting for the consumer to act
  # accordingly
  busy: bool = False
  queued_messages: deque[OpenChannelMessage] = field(default_factory=deque)

  # True if we have sent a SSH_MSG_CHANNEL_CLOSE and are waiting for the remote
  # side to send a SSH_MSG_CHANNEL_CLOSE
  dead: bool = False

  inner: SessionInnerChannel
  remote_id: int

@dataclass(slots=True)
class SessionInnerChannel:
  env: dict[str, str] = field(default_factory=dict, init=False)
  pty: Optional[SessionPTYOptions] = field(default=None, init=False)


@dataclass(kw_only=True)
class SansIOConnection:
  debug: bool
  settings: SansIOConnectionSettings

  _authenticated: bool = field(default=False, init=False)
  _terminated: bool = field(default=False, init=False)

  _client_ident_string: Optional[IdentString] = field(default=None, init=False)
  _server_ident_string: IdentString = field(init=False)

  _sequence_number_in: int = field(default=0, init=False)
  _sequence_number_out: int = field(default=0, init=False)
  _session_id: Optional[bytes] = field(default=None, init=False)

  # Initialized after key exchange is complete
  _transmitted_byte_count: int = field(init=False)

  _key_exchange: Optional[MessageFlow[None]] = field(default=None, init=False)

  # Queue of messages that cannot be sent to due to an ongoing key exchange
  _queued_messages: list[Message] = field(default_factory=list, init=False)

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

  _channels: dict[int, Channel] = field(default_factory=dict, init=False)
  _next_channel_id: int = field(default=0, init=False)

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

  def _send_or_queue_message(self, message: Message):
    if self._key_exchange is not None:
      self._queued_messages.append(message)
    else:
      self._send_message(message)


  def close(self):
    if self._terminated:
      raise ConnectionTerminatedError

    LOGGER.debug('Disconnected by server')

    self._disconnect(
      DisconnectReason.ByApplication,
      'Connection closed by application',
    )

  def trigger_key_exchange(self):
    if self._terminated:
      raise ConnectionTerminatedError

    if self._client_ident_string is None:
      raise RuntimeError('Key exchange cannot be run before the client identification string is received')

    if self._key_exchange is not None:
      return

    self._key_exchange = iter(self._run_key_exchange())
    next(self._key_exchange)


  def events(self) -> Iterator[Event]:
    # Not checking whether terminated in order to send DisconnectMessage to the
    # client

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
    if self._terminated:
      raise ConnectionTerminatedError

    self._receive_buffer += chunk

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
        self._disconnect(
          DisconnectReason.ProtocolVersionNotSupported,
          'Protocol version not supported',
        )

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

        if not bytes_eq(digest, produced_digest):
          self._disconnect(
            DisconnectReason.MacError,
            'MAC error',
          )

          return


      # Return payload

      self._sequence_number_in += 1

      if len(payload) < 1:
        raise ProtocolError

      self._receive_message(MessageStub(payload), sequence_number)

  def _disconnect(self, reason_code: DisconnectReason, description: str):
    self._send_message(
      DisconnectMessage(
        reason_code=reason_code,
        description=description,
        language_tag='',
      ),
    )

    self._terminated = True

  def _receive_message(self, message_stub: MessageStub, sequence_number: int):
    LOGGER.debug(f'Received message id {message_stub.id} (sequence number {sequence_number})')

    try:
      match message_stub.id:
        case DisconnectMessage.id:
          message = message_stub.decode(DisconnectMessage)
          self._terminated = True

          LOGGER.debug(f'Disconnected by client: reason={DisconnectReason(message.reason_code).name!r} description={message.description!r}')

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

        case ExtInfoMessage.id:
          if self._encryption_in is None:
            raise ProtocolError

          _ext_info = message_stub.decode(ExtInfoMessage)

        case ServiceRequestMessage.id:
          if (self._encryption_in is None) or (self._key_exchange is not None):
            raise ProtocolError

          message = message_stub.decode(ServiceRequestMessage)

          match message.service_name:
            case 'ssh-userauth':
              if self._authenticated:
                raise ProtocolError

              self._send_message(
                ServiceAcceptMessage(service_name=message.service_name),
              )
            case _:
              self._disconnect(DisconnectReason.ServiceNotAvailable, 'Service not available')
        case UserAuthRequestMessage.id:
          if (self._encryption_in is None) or (self._key_exchange is not None):
            raise ProtocolError

          if self._authenticated:
            raise ProtocolError

          message = message_stub.decode(UserAuthRequestMessage)

          if message.type in self.settings.supported_auth_methods:
            match message.details:
              case UserAuthRequestDetailsPassword(password=password, new_password=None):
                def respond(success: bool):
                  if success:
                    self._send_message(UserAuthSuccessMessage())
                    self._authenticated = True
                  else:
                    self._send_message(UserAuthFailureMessage(
                      supported_methods=list(self.settings.supported_auth_methods),
                      partial_success=False,
                    ))

                self._events.append(AuthWithPasswordRequestEvent(
                  user_name=message.user_name,
                  password=password,
                  respond=respond,
                ))

              case UserAuthRequestDetailsPublicKey(algorithm=algorithm, public_key=public_key, signature=signature):
                def respond(success: bool):
                  if success:
                    if signature is None:
                      self._send_message(UserAuthPublicKeyOk(
                        algorithm=algorithm,
                        public_key=public_key,
                      ))
                    else:
                      self._send_message(UserAuthSuccessMessage())
                      self._authenticated = True
                  else:
                    self._send_message(UserAuthFailureMessage(
                      supported_methods=list(self.settings.supported_auth_methods),
                      partial_success=False,
                    ))

                self._events.append(AuthWithPublicKeyRequestEvent(
                  user_name=message.user_name,
                  algorithm=algorithm,
                  public_key=public_key,
                  authenticating=(signature is not None),
                  respond=respond,
                ))

              case _:
                raise ProtocolError
          else:
            self._send_message(UserAuthFailureMessage(
              supported_methods=list(self.settings.supported_auth_methods),
              partial_success=False,
            ))

        case ChannelOpenMessage.id:
          if (self._encryption_in is None) or (self._key_exchange is not None) or (not self._authenticated):
            raise ProtocolError

          message = message_stub.decode(ChannelOpenMessage)

          if message.sender_channel_id in self._channels:
            raise ProtocolError

          match message.details:
            case ChannelOpenDetailsSession():
              inner_channel = SessionInnerChannel()
            case _:
              raise NotImplementedError

          channel = Channel(
            inner=inner_channel,
            remote_id=message.sender_channel_id,
          )

          def accept_channel_open():
            if self._terminated:
              raise ConnectionTerminatedError

            channel_id = self._next_channel_id
            self._next_channel_id += 1

            self._channels[channel_id] = channel

            self._send_or_queue_message(
              ChannelOpenConfirmationMessage(
                recipient_channel_id=message.sender_channel_id,
                sender_channel_id=channel_id,
                window_size=message.window_size,
                max_packet_size=message.max_packet_size,
              ),
            )

            return channel_id

          def reject_channel_open(reason: ChannelOpenFailureReason, description: str):
            if self._terminated:
              raise ConnectionTerminatedError

            self._send_or_queue_message(
              ChannelOpenFailureMessage(
                recipient_channel_id=message.sender_channel_id,
                reason_code=reason,
                description=description,
                language_tag='',
              ),
            )

          self._events.append(
            ChannelOpenEvent(
              message,
              accept=accept_channel_open,
              reject=reject_channel_open,
            ),
          )

        case ChannelRequestMessage.id | ChannelDataMessage.id | ChannelEofMessage.id:
          if (self._encryption_in is None) or (self._key_exchange is not None) or (not self._authenticated):
            raise ProtocolError

          # TODO: Allow decode() to accept and return a union
          match message_stub.id:
            case ChannelRequestMessage.id:
              message = message_stub.decode(ChannelRequestMessage)
            case ChannelDataMessage.id:
              message = message_stub.decode(ChannelDataMessage)
            case ChannelEofMessage.id:
              message = message_stub.decode(ChannelEofMessage)
            case _:
              raise UnreachableError

          channel = self._channels.get(message.recipient_channel_id)

          if (channel is None) or channel.dead:
            raise ProtocolError

          channel.queued_messages.append(message)
          self._receive_channel_messages(channel)

        case ChannelCloseMessage.id:
          if (self._encryption_in is None) or (self._key_exchange is not None) or (not self._authenticated):
            raise ProtocolError

          message = message_stub.decode(ChannelCloseMessage)
          channel = self._channels.get(message.recipient_channel_id)

          if channel is None:
            raise ProtocolError

          if not channel.dead:
            self._send_message(
              ChannelCloseMessage(
                recipient_channel_id=channel.remote_id,
              ),
            )

          del self._channels[message.recipient_channel_id]

        case _:
          self._disconnect(DisconnectReason.ProtocolError, f'Unsupported message id {message_stub.id}')

          if self.debug:
            raise NotImplementedError(f'Unsupported message id {message_stub.id}')

    except NotImplementedError, ProtocolError:
      self._disconnect(DisconnectReason.ProtocolError, 'Protocol error')

      if self.debug:
        raise

  def _receive_channel_messages(self, channel: Channel):
    while channel.queued_messages and not channel.busy: # TODO: Why the channel.busy check?
      message = channel.queued_messages.popleft()
      # print(f'Processing queued message {message} for channel with remote id {channel.remote_id}')

      match message:
        case ChannelDataMessage():
          self._events.append(
            ChannelDataEvent(
              channel_id=channel.remote_id,
              chunk=message.data,
            ),
          )

        case ChannelEofMessage():
          self._events.append(
            ChannelEofEvent(
              channel_id=channel.remote_id,
            ),
          )

        case ChannelRequestMessage():
          match message.details:
            case ChannelRequestDetailsExec() | ChannelRequestDetailsShell():
              def exit(exit_status: int):
                if channel.dead:
                  return

                self._send_message(
                  ChannelRequestMessage(
                    recipient_channel_id=channel.remote_id,
                    request_type='exit-status',
                    want_reply=False,
                    details=ChannelRequestDetailsExitStatus(exit_status=exit_status),
                  ),
                )

                self._send_message(
                  ChannelCloseMessage(
                    recipient_channel_id=channel.remote_id,
                  ),
                )

                channel.dead = True

              def write(chunk: bytes):
                if channel.dead:
                  return

                self._send_message(
                  ChannelDataMessage(
                    recipient_channel_id=channel.remote_id,
                    data=chunk,
                  ),
                )

              def accept():
                assert isinstance(message, ChannelRequestMessage)

                if message.want_reply:
                  self._send_or_queue_message(
                    ChannelSuccessMessage(
                      recipient_channel_id=channel.remote_id,
                    ),
                  )

                channel.busy = False
                self._receive_channel_messages(channel)

                return Stream(exit=exit, write=write)

              def reject():
                self._send_or_queue_message(
                  ChannelFailureMessage(
                    recipient_channel_id=channel.remote_id,
                  ),
                )

                channel.busy = False

              match message.details:
                case ChannelRequestDetailsExec():
                  event = SessionExecEvent(
                    command=message.details.command,
                    env=channel.inner.env,
                    pty=channel.inner.pty,

                    accept=accept,
                    reject=reject,
                  )
                case ChannelRequestDetailsShell():
                  event = SessionShellEvent(
                    env=channel.inner.env,
                    pty=channel.inner.pty,

                    accept=accept,
                    reject=reject,
                  )
                case _:
                  raise UnreachableError

              self._events.append(event)
              channel.busy = True

            case ChannelRequestDetailsEnv():
              if not isinstance(channel.inner, SessionInnerChannel):
                raise ProtocolError

              if message.details.name in channel.inner.env:
                raise ProtocolError

              channel.inner.env[message.details.name] = message.details.value

              if message.want_reply:
                self._send_message(
                  ChannelSuccessMessage(
                    recipient_channel_id=channel.remote_id,
                  ),
                )

            case ChannelRequestDetailsPtyReq():
              if not isinstance(channel.inner, SessionInnerChannel):
                raise ProtocolError

              if channel.inner.pty is not None:
                raise ProtocolError

              channel.inner.pty = SessionPTYOptions(
                terminal_modes=message.details.term_modes,
                terminal_name=message.details.term_name,
                window_chars=(message.details.term_width_chars, message.details.term_height_chars),
                window_pixels=(message.details.term_width_pixels, message.details.term_height_pixels),
              )

              if message.want_reply:
                self._send_message(
                  ChannelSuccessMessage(
                    recipient_channel_id=channel.remote_id,
                  ),
                )

            case _:
              print('Not handled', message.details)

        case _:
          # typing.assert_never(message)
          # raise UnreachableError

          raise NotImplementedError


  def _run_key_exchange(self) -> MessageFlow[None]:
    assert self._key_exchange is not None

    is_first = self._session_id is None

    usable_server_host_key_algorithms = functools.reduce(operator.or_, (key.algorithms() for key in self.settings.host_keys), set())
    server_supported_algorithms = copy.deepcopy(self.settings.supported_algorithms)
    server_supported_algorithms.server_host_key_algorithms = [
      algorithm for algorithm in self.settings.supported_algorithms.server_host_key_algorithms if algorithm in usable_server_host_key_algorithms
    ]

    server_kex_init_payload = self._send_message(
      KexInitMessage(
        kex_algorithms=(server_supported_algorithms.kex_algorithms + (['ext-info-s'] if is_first else [])),
        server_host_key_algorithms=list(server_supported_algorithms.server_host_key_algorithms),
        encryption_algorithms_client_to_server=list(server_supported_algorithms.encryption_algorithms_client_to_server),
        encryption_algorithms_server_to_client=list(server_supported_algorithms.encryption_algorithms_server_to_client),
        mac_algorithms_client_to_server=list(server_supported_algorithms.mac_algorithms_client_to_server),
        mac_algorithms_server_to_client=list(server_supported_algorithms.mac_algorithms_server_to_client),
        compression_algorithms_client_to_server=list(server_supported_algorithms.compression_algorithms_client_to_server),
        compression_algorithms_server_to_client=list(server_supported_algorithms.compression_algorithms_server_to_client),
        languages_client_to_server=[],
        languages_server_to_client=[],
        first_kex_packet_follows=False,
      ),
    )

    client_kex_init_stub = yield
    client_kex_init = client_kex_init_stub.decode(KexInitMessage)
    client_kex_init_payload = client_kex_init_stub.payload


    # Negotiate algorithms

    algorithm_selection = server_supported_algorithms.negotiate(client_kex_init)
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
          'server-sig-algs': encode_name_list(extract(SignatureAlgorithmName)),
        }),
      )

    self._events.append(ExchangedKeysEvent())
    self._key_exchange = None


    # Send queued messages

    for queued_message in self._queued_messages:
      self._send_message(queued_message)

    self._queued_messages.clear()
