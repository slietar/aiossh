import functools
import logging
import operator
import struct
from asyncio import StreamReader, StreamWriter, TaskGroup
from collections.abc import Awaitable
from dataclasses import dataclass, field
from pprint import pprint
from typing import TYPE_CHECKING, Optional

import aiodrive

from .abstract.client import Client
from .abstract.session import SessionExitSignal, SessionExitStatus
from .algorithms import AlgorithmSelection, AlgorithmSets
from .encryption.base import Encryption
from .encryption.resolve import resolve_encryption
from .error import (
  AlgorithmNegotiationError,
  ConnectionClosedError,
  IntegrityVerificationError,
  ProtocolError,
  ProtocolVersionNotSupportedError,
  UnreachableError,
)
from .flow import MessageFlow
from .ident_string import IdentString
from .integrity.base import IntegrityVerification
from .integrity.resolve import (
  resolve_integrity_verification,
)
from .key_exchange.resolve import resolve_key_exchange
from .messages.base import EncodableMessage
from .messages.channel import (
  ChannelCloseMessage,
  ChannelDataMessage,
  ChannelEofMessage,
  ChannelOpenConfirmationMessage,
  ChannelOpenDetailsSession,
  ChannelOpenFailureMessage,
  ChannelOpenFailureReason,
  ChannelOpenMessage,
)
from .messages.channel_request import (
  ChannelFailureMessage,
  ChannelRequestDetailsEnv,
  ChannelRequestDetailsExitSignal,
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
  UnimplementedMessage,
)
from .messages.key_exchange import KexInitMessage
from .messages.service import ServiceAcceptMessage, ServiceRequestMessage
from .messages.user_auth import UserAuthRequestMessage
from .packet import encode_packet
from .public.base import PrivateKey
from .reader import Reader
from .session import Session, SessionActivity, SessionPTY
from .stream import AsyncWritableStreamImpl
from .structures.primitives import encode_mpint, encode_name_list
from .user_auth import run_user_auth


if TYPE_CHECKING:
  from .server import Server


logger = logging.getLogger(__name__)



# @dataclass(slots=True)
# class DraftSessionPTY:
#   term_name: bytes
#   term_width_chars: int
#   term_height_chars: int
#   term_width_pixels: int
#   term_height_pixels: int
#   term_modes: TerminalModes

# @dataclass(slots=True)
# class DraftSession:
#   env: dict[str, str] = field(default_factory=dict)
#   pty: Optional[DraftSessionPTY] = None


@dataclass(repr=False, slots=True)
class Connection:
  server: Server
  client: Client

  reader: StreamReader
  writer: StreamWriter

  debug: bool = True

  client_ident_string: Optional[IdentString] = field(default=None, init=False)
  server_ident_string: Optional[IdentString] = field(default=None, init=False)

  algorithm_selection: Optional[AlgorithmSelection] = field(default=None, init=False)
  encryption_in: Optional[Encryption] = field(default=None, init=False)
  encryption_out: Optional[Encryption] = field(default=None, init=False)
  host_key: Optional[PrivateKey] = field(default=None, init=False)
  integrity_verification_in: Optional[IntegrityVerification] = field(default=None, init=False)
  integrity_verification_out: Optional[IntegrityVerification] = field(default=None, init=False)

  sequence_number_in: int = field(default=0, init=False)
  sequence_number_out: int = field(default=0, init=False)
  session_id: Optional[bytes] = None

  authenticated: bool = False
  key_exchange_flow: Optional[MessageFlow] = None
  user_auth_flow: Optional[MessageFlow] = None

  next_session_id: int = field(default=8345, init=False)
  sessions: dict[int, Session] = field(default_factory=dict, init=False)


  async def read(self, byte_count: int, /):
    # The read byte count may be zero.

    data = b''

    while len(data) < byte_count:
      try:
        chunk = await self.reader.read(byte_count - len(data))
      except ConnectionError as e: # Parent class of BrokenPipeError, ConnectionResetError, and others
        raise ConnectionClosedError from e

      if not chunk:
        raise ConnectionClosedError

      data += chunk

    return data


  async def read_message(self):
    block_size_or_zero = self.encryption_in.block_size() if self.encryption_in is not None else 0
    digest_size_or_zero = self.integrity_verification_in.digest_size if self.integrity_verification_in is not None else 0


    # Read packet length (without the length itself) or first block

    packet_length_size = 4
    padding_length_size = 1

    if self.encryption_in is not None:
      packet_with_length = self.encryption_in.decrypt_blocks(
        await self.read(self.encryption_in.block_size()),
      )
    else:
      packet_with_length = await self.read(packet_length_size)


    # Read rest of packet
    # See: RFC 4253 Section 6

    packet_length_bytes = packet_with_length[:packet_length_size]
    packet_length = struct.unpack('>I', packet_length_bytes)[0]

    # The packet must at least contain the padding length byte.
    if packet_length < padding_length_size:
      raise ProtocolError

    # The total packet size, with length and MAC, must not exceed 35,000 bytes.
    if packet_length_size + packet_length + digest_size_or_zero > 35000:
      raise ProtocolError

    if self.encryption_in is not None:
      missing_block_count = (packet_length_size + packet_length - 1) // self.encryption_in.block_size()
      packet_with_length += self.encryption_in.decrypt_blocks(
        await self.read(self.encryption_in.block_size() * missing_block_count),
      )

      packet_after_length = packet_with_length[packet_length_size:]
    else:
      packet_after_length = await self.read(packet_length)
      packet_with_length += packet_after_length

    padding_length = packet_after_length[0]
    payload_length = packet_length - padding_length - padding_length_size

    padding_alignment = max(block_size_or_zero, 8)

    # Packet size without the mac
    packet_size = packet_length_size + padding_length_size + payload_length + padding_length

    if (payload_length < 0) or (packet_size % padding_alignment) != 0 or (packet_size < max(block_size_or_zero, 16)):
      raise ProtocolError

    payload = packet_after_length[padding_length_size:(padding_length_size + payload_length)]

    # TODO: Compression + check if uncompressed size is < 32,768 bytes (RFC 4253 Section 6.1)


    # Verify integrity using MAC
    # See: RFC 4253 Section 6.4

    sequence_number = self.sequence_number_in

    if self.integrity_verification_in is not None:
      expected_digest = await self.read(self.integrity_verification_in.digest_size)

      self.integrity_verification_in.start(sequence_number)
      self.integrity_verification_in.update(packet_with_length)
      produced_digest = self.integrity_verification_in.digest()

      if expected_digest != produced_digest:
        raise IntegrityVerificationError


    # Return payload

    self.sequence_number_in += 1

    return payload, sequence_number

  def write_message(self, message: EncodableMessage):
    payload = message.encode_payload()
    sized_packet = encode_packet(
      payload,
      block_size=(self.encryption_out.block_size() if self.encryption_out else None),
    )

    if self.encryption_out is not None:
      self.writer.write(self.encryption_out.encrypt_blocks(sized_packet))
    else:
      self.writer.write(sized_packet)

    if self.integrity_verification_out is not None:
      self.integrity_verification_out.start(self.sequence_number_out)
      self.integrity_verification_out.update(sized_packet)
      self.writer.write(self.integrity_verification_out.digest())

    self.sequence_number_out += 1

    # Return payload because the KexInit message payload is reused for key exchange
    return payload


  async def run_key_exchange(self):
    # See: RFC 4253 Section 7

    # Create key exchange flow

    assert self.key_exchange_flow is None
    self.key_exchange_flow = MessageFlow()
    read_message = self.key_exchange_flow.read


    # Send server KexInit message

    supported_algorithms = AlgorithmSets()
    supported_algorithms.server_host_key_algorithms &= functools.reduce(operator.or_, (key.algorithms() for key in self.server.host_keys))

    server_kex_init = KexInitMessage(
      kex_algorithms=['ext-info-s', *supported_algorithms.kex_algorithms],
      server_host_key_algorithms=list(supported_algorithms.server_host_key_algorithms),
      encryption_algorithms_client_to_server=list(supported_algorithms.encryption_algorithms_client_to_server),
      encryption_algorithms_server_to_client=list(supported_algorithms.encryption_algorithms_server_to_client),
      mac_algorithms_client_to_server=list(supported_algorithms.mac_algorithms_client_to_server),
      mac_algorithms_server_to_client=list(supported_algorithms.mac_algorithms_server_to_client),
      compression_algorithms_client_to_server=list(supported_algorithms.compression_algorithms_client_to_server),
      compression_algorithms_server_to_client=list(supported_algorithms.compression_algorithms_server_to_client),
      languages_client_to_server=[],
      languages_server_to_client=[],
      first_kex_packet_follows=False,
    )

    server_kex_init_payload = self.write_message(server_kex_init)
    read_client_kex_init = read_message(KexInitMessage)


    # Read client KexInit message

    client_kex_init, client_kex_init_payload = await read_client_kex_init


    # Negotiate algorithms

    self.algorithm_selection = supported_algorithms.negotiate(client_kex_init)
    self.host_key = next(key for key in self.server.host_keys if self.algorithm_selection.server_host_key_algorithm in key.algorithms())


    # Ignore next packet if the preferred algorithms do not match

    if client_kex_init.first_kex_packet_follows and (
      (self.algorithm_selection.kex_algorithm != client_kex_init.kex_algorithms[0])
      or (self.algorithm_selection.server_host_key_algorithm != client_kex_init.server_host_key_algorithms[0])
      or (self.algorithm_selection.encryption_algorithm_client_to_server != client_kex_init.encryption_algorithms_client_to_server[0])
      or (self.algorithm_selection.encryption_algorithm_server_to_client != client_kex_init.encryption_algorithms_server_to_client[0])
      or (self.algorithm_selection.mac_algorithm_client_to_server != client_kex_init.mac_algorithms_client_to_server[0])
      or (self.algorithm_selection.mac_algorithm_server_to_client != client_kex_init.mac_algorithms_server_to_client[0])
    ):
      # TODO: Skip next packet
      raise NotImplementedError


    # Run key exchange

    key_exchange = resolve_key_exchange(self.algorithm_selection.kex_algorithm)

    exchange_hash, shared_key = await key_exchange.run(
      self,
      read_message,
      client_kex_init_payload,
      server_kex_init_payload,
    )


    # Compute key exchange output
    # See: RFC 4253 Section 7.2

    if self.session_id is None:
      self.session_id = exchange_hash

    session_id = self.session_id
    encoded_shared_secret = encode_mpint(int.from_bytes(shared_key))

    def derive_key(letter: bytes, size: int):
      key = key_exchange.hash(encoded_shared_secret + exchange_hash + letter + session_id)

      while len(key) < size:
        key += key_exchange.hash(encoded_shared_secret + exchange_hash + key)

      return key[:size]


    # Establish output algorithms

    self.write_message(NewKeysMessage())

    EncryptionOut = resolve_encryption(self.algorithm_selection.encryption_algorithm_server_to_client)

    self.encryption_out = EncryptionOut(
      key=derive_key(b'D', EncryptionOut.key_size()),
      iv=derive_key(b'B', EncryptionOut.block_size()),
    )

    self.integrity_verification_out = resolve_integrity_verification(self.algorithm_selection.mac_algorithm_server_to_client)
    self.integrity_verification_out.build(
      derive_key(b'F', self.integrity_verification_out.key_size),
    )


    # Establish input algorithms

    await read_message(NewKeysMessage)

    EncryptionIn = resolve_encryption(self.algorithm_selection.encryption_algorithm_client_to_server)

    self.encryption_in = EncryptionIn(
      key=derive_key(b'C', EncryptionIn.key_size()),
      iv=derive_key(b'A', EncryptionIn.block_size()),
    )

    self.integrity_verification_in = resolve_integrity_verification(self.algorithm_selection.mac_algorithm_client_to_server)
    self.integrity_verification_in.build(
      derive_key(b'E', self.integrity_verification_in.key_size),
    )

    logger.debug('Done with key exchange')


    # Send extensions

    # TODO: Only send on first key exchange
    self.write_message(ExtInfoMessage(extensions={
      'server-sig-algs': encode_name_list([
        'rsa-sha2-256',
        'rsa-sha2-512',
        # TODO: List all supported algorithms
      ]),
    }))


    # Finish flow

    self.key_exchange_flow = None


  async def start_user_auth(self):
    self.user_auth_flow = MessageFlow()

    try:
      self.authenticated = await run_user_auth(self, self.user_auth_flow.read)
    finally:
      self.user_auth_flow = None


  async def handle(self):
    try:
      try:
        # Send server ident string

        self.server_ident_string = IdentString(
          comment=None,
          software_version=self.server.software_version,
        )

        self.writer.write(bytes(self.server_ident_string) + b'\r\n')


        # Read client ident string

        # TODO: Improve safety
        client_ident_string_terminated = await self.reader.readuntil(b'\r\n')

        if len(client_ident_string_terminated) > 0xff:
          raise ProtocolError

        try:
          self.client_ident_string = IdentString.decode(client_ident_string_terminated[:-2])
        except ProtocolVersionNotSupportedError:
          self.write_message(DisconnectMessage(
            reason_code=DisconnectReason.ProtocolVersionNotSupported,
            description='Protocol version not supported',
            language_tag='',
          ))

          return

        logger.debug(f'Client version: "{self.client_ident_string.software_version}"')


        # Listen for messages

        async def wrap[T](awaitable: Awaitable[T], /):
          return await awaitable

        async with TaskGroup() as group:
          while True:
            message_payload, message_sequence_number = await self.read_message()

            if len(message_payload) < 1:
              raise ProtocolError

            message_id = message_payload[0]

            logger.debug(f'Received message id {message_id} (sequence number {message_sequence_number})')

            # See: RFC 4250 Section 4.1

            match message_id:
              case DisconnectMessage.id:
                message = DisconnectMessage.decode_payload(message_payload)
                log_string = 'Client disconnected with reason '

                try:
                  reason = DisconnectReason(message.reason_code)
                except ValueError:
                  log_string += f'{message.reason_code}'
                else:
                  log_string += f'{reason.name}'

                if message.description:
                  log_string += f' and message "{message.description}"'

                logger.error(log_string)
                return

              case KexInitMessage.id:
                if self.key_exchange_flow is None:
                  group.create_task(wrap(aiodrive.prime(self.run_key_exchange())), name='key_exchange')

                assert self.key_exchange_flow is not None
                await self.key_exchange_flow.feed(message_id, message_payload)

              case _ if (message_id == NewKeysMessage.id) or (30 <= message_id <= 49):
                if self.key_exchange_flow is None:
                  raise ProtocolError

                await self.key_exchange_flow.feed(message_id, message_payload)

              case ExtInfoMessage.id:
                ext_info = ExtInfoMessage.decode_payload(message_payload)
                logger.debug(f'Received extension info: {', '.join(ext_info.extensions.keys())}')

              case ServiceRequestMessage.id:
                if self.key_exchange_flow is not None:
                  raise ProtocolError

                message_payload_io = Reader(message_payload[1:])
                service_request = ServiceRequestMessage.decode(message_payload_io)

                match service_request.service_name:
                  case 'ssh-userauth':
                    self.write_message(ServiceAcceptMessage(service_name=service_request.service_name))
                  case _:
                    self.write_message(DisconnectMessage(
                      reason_code=DisconnectReason.ServiceNotAvailable,
                      description='Service not available',
                      language_tag='',
                    ))

                    return

              case UserAuthRequestMessage.id:
                if self.user_auth_flow is not None:
                  raise ProtocolError

                group.create_task(wrap(aiodrive.prime(self.start_user_auth())), name='user_auth')

                assert self.user_auth_flow is not None
                await self.user_auth_flow.feed(message_id, message_payload) # type: ignore

              case ChannelOpenMessage.id:
                message = ChannelOpenMessage.decode_payload(message_payload)

                match message.details:
                  case ChannelOpenDetailsSession():
                    logger.debug(f'Opening channel of type {type(message.details).__name__}')

                    session_id = self.next_session_id
                    self.next_session_id += 1

                    self.sessions[session_id] = Session(client_channel_id=message.sender_channel_id)

                    self.write_message(
                      ChannelOpenConfirmationMessage(
                        recipient_channel_id=message.sender_channel_id,
                        sender_channel_id=session_id,
                        window_size=message.window_size,
                        max_packet_size=message.max_packet_size,
                        # details=message.details,
                      ),
                    )

                  case _:
                    self.write_message(
                      ChannelOpenFailureMessage(
                        recipient_channel_id=message.sender_channel_id,
                        reason_code=ChannelOpenFailureReason.UnknownChannelType,
                        description='Unknown channel type',
                        language_tag='',
                      ),
                    )

              case ChannelRequestMessage.id:
                message = ChannelRequestMessage.decode_payload(message_payload)
                session = self.sessions.get(message.recipient_channel_id)

                if session is None:
                  raise ProtocolError

                client_channel_id = session.client_channel_id

                match message.details:
                  case ChannelRequestDetailsEnv(name=name, value=value):
                    success = self.client.set_session_env(name, value)

                    if success:
                      logger.debug(f'Setting environment variable {name}={value}')
                      session.settings.env[name] = value

                      if message.want_reply:
                        self.write_message(ChannelSuccessMessage(
                          recipient_channel_id=message.recipient_channel_id,
                        ))

                  case ChannelRequestDetailsPtyReq():
                    logger.debug('Allocating PTY')
                    success = session.settings.pty is None

                    if success:
                      session.settings.pty = SessionPTY(
                        terminal_modes=message.details.term_modes,
                        terminal_name=message.details.term_name,
                        window_chars=(message.details.term_width_chars, message.details.term_height_chars),
                        window_pixels=(message.details.term_width_pixels, message.details.term_height_pixels),
                      )

                  case ChannelRequestDetailsShell():
                    logger.debug('Starting shell')

                    try:
                      coro = self.client.start_shell(session)
                    except NotImplementedError:
                      logger.debug('Shell not implemented by client')
                      success = False
                    else:
                      async def write_stdout(chunk: Optional[bytes], /):
                        if chunk is not None:
                          # TODO: Split chunk

                          self.write_message(
                            ChannelDataMessage(
                              recipient_channel_id=client_channel_id,
                              data=chunk,
                            ),
                          )
                        else:
                          self.write_message(
                            ChannelEofMessage(
                              recipient_channel_id=client_channel_id,
                            ),
                          )

                      session.activity = SessionActivity(
                        stdout=AsyncWritableStreamImpl(write_stdout),
                        stderr=AsyncWritableStreamImpl(write_stdout),
                      )

                      success = True

                      async def session_handler():
                        result = await coro

                        match result:
                          case SessionExitStatus(status):
                            self.write_message(
                              ChannelRequestMessage(
                                recipient_channel_id=client_channel_id,
                                request_type='exit-status', # TODO: Remove this
                                want_reply=False,
                                details=ChannelRequestDetailsExitStatus(exit_status=status),
                              ),
                            )
                          case SessionExitSignal():
                            self.write_message(
                              ChannelRequestMessage(
                                recipient_channel_id=client_channel_id,
                                request_type='exit-signal', # TODO: Remove this
                                want_reply=False,
                                details=ChannelRequestDetailsExitSignal(
                                  signal_name=result.signal_name,
                                  core_dumped=result.core_dumped,
                                  error_message=result.error_message,
                                  language_tag=result.language_tag,
                                ),
                              ),
                            )
                          case _:
                            raise UnreachableError

                        self.write_message(
                          ChannelCloseMessage(
                            recipient_channel_id=client_channel_id,
                          ),
                        )

                      group.create_task(session_handler())

                  # case ChannelRequestDetailsExec(command):
                  #   logger.debug(f'Executing command: "{command}"')
                  #   success = True

                  #   session.activity = SessionActivity()

                  case _:
                    print('Unsupported channel request details')
                    pprint(message)

                    raise ProtocolError

                if message.want_reply:
                  if success:
                    self.write_message(ChannelSuccessMessage(
                      recipient_channel_id=client_channel_id,
                    ))
                  else:
                    self.write_message(ChannelFailureMessage(
                      recipient_channel_id=client_channel_id,
                    ))

              case ChannelCloseMessage.id:
                message = ChannelCloseMessage.decode_payload(message_payload)
                session = self.sessions.pop(message.recipient_channel_id, None) # TODO: Improve

                if session is None:
                  raise ProtocolError

              case ChannelDataMessage.id:
                message = ChannelDataMessage.decode_payload(message_payload)
                session = self.sessions.get(message.recipient_channel_id)

                if (session is None) or (session.activity is None):
                  raise ProtocolError

                print(f'Received {message.data!r}')
                session.activity.stdin._feed(message.data)
                # session.activity.stdin._feed(message.data.replace(b'\r', b'\n'))

              case _:
                self.write_message(UnimplementedMessage(message_sequence_number))

                if self.debug:
                  raise ProtocolError(f'Unknown message id {message_id}')

      except AlgorithmNegotiationError:
        self.write_message(DisconnectMessage(
          reason_code=DisconnectReason.KeyExchangeFailed,
          description='Key exchange failed',
          language_tag='',
        ))

        if self.debug:
          raise

      except IntegrityVerificationError:
        self.write_message(DisconnectMessage(
          reason_code=DisconnectReason.MacError,
          description='Integrity verification error',
          language_tag='',
        ))

        if self.debug:
          raise

      except ProtocolError:
        self.write_message(DisconnectMessage(
          reason_code=DisconnectReason.ProtocolError,
          description='Protocol error',
          language_tag='',
        ))

        if self.debug:
          raise

    except* ConnectionClosedError:
      pass

    finally:
      self.writer.close()
      logger.debug('Closed connection')
