import asyncio
import struct
from asyncio import StreamReader, StreamWriter
from dataclasses import dataclass, field
from pprint import pprint
from typing import TYPE_CHECKING, Optional

from aiodrive import Pool, prime

from .client import BaseClient
from .encryption.base import Encryption
from .encryption.resolve import resolve_encryption
from .error import ConnectionClosedError, ProtocolError
from .flow import MessageFlow
from .host_key import HostKey
from .ident_string import IdentString
from .integrity.base import IntegrityVerification
from .integrity.resolve import resolve_integrity_verification
from .key_exchange.resolve import resolve_key_exchange
from .messages.base import EncodableMessage
from .messages.channel import (ChannelOpenConfirmationMessage,
                               ChannelOpenFailureMessage,
                               ChannelOpenFailureReason, ChannelOpenMessage,
                               ChannelOpenUnknownMessage)
from .messages.channel_request import ChannelRequestMessage
from .messages.kex_init import KexInitMessage
from .messages.misc import (NewKeysMessage, ServiceAcceptMessage,
                            ServiceRequestMessage)
from .messages.user_auth import UserAuthRequestMessage
from .packet import encode_packet
from .structures.primitives import encode_mpint
from .user_auth import run_user_auth
from .util import ReadableBytesIOImpl

if TYPE_CHECKING:
  from .server import Server


@dataclass(frozen=True, kw_only=True, slots=True)
class AlgorithmSelection:
  kex_algorithm: str
  server_host_key_algorithm: str
  encryption_algorithm_client_to_server: str
  encryption_algorithm_server_to_client: str
  mac_algorithm_client_to_server: str
  mac_algorithm_server_to_client: str


def negotiate_algorithms(client: KexInitMessage, server: KexInitMessage):
  # See: RFC 4253 Section 7.1

  kex_algorithm = next((algorithm for algorithm in client.kex_algorithms if algorithm in server.kex_algorithms), None)
  server_host_key_algorithm = next((algorithm for algorithm in client.server_host_key_algorithms if algorithm in server.server_host_key_algorithms), None)
  encryption_algorithm_client_to_server = next((algorithm for algorithm in client.encryption_algorithms_client_to_server if algorithm in server.encryption_algorithms_client_to_server), None)
  encryption_algorithm_server_to_client = next((algorithm for algorithm in client.encryption_algorithms_server_to_client if algorithm in server.encryption_algorithms_server_to_client), None)
  mac_algorithm_client_to_server = next((algorithm for algorithm in client.mac_algorithms_client_to_server if algorithm in server.mac_algorithms_client_to_server), None)
  mac_algorithm_server_to_client = next((algorithm for algorithm in client.mac_algorithms_server_to_client if algorithm in server.mac_algorithms_server_to_client), None)

  if (kex_algorithm is None)\
    or (server_host_key_algorithm is None)\
    or (encryption_algorithm_client_to_server is None)\
    or (encryption_algorithm_server_to_client is None)\
    or (mac_algorithm_client_to_server is None)\
    or (mac_algorithm_server_to_client is None):
    raise ProtocolError('Algorithm negotiation failure')

  return AlgorithmSelection(
    kex_algorithm=kex_algorithm,
    server_host_key_algorithm=server_host_key_algorithm,
    encryption_algorithm_client_to_server=encryption_algorithm_client_to_server,
    encryption_algorithm_server_to_client=encryption_algorithm_server_to_client,
    mac_algorithm_client_to_server=mac_algorithm_client_to_server,
    mac_algorithm_server_to_client=mac_algorithm_server_to_client
  )


@dataclass(repr=False, slots=True)
class Connection:
  server: 'Server'
  client: BaseClient

  reader: StreamReader
  writer: StreamWriter

  client_ident_string: Optional[IdentString] = field(default=None, init=False)
  server_ident_string: Optional[IdentString] = field(default=None, init=False)

  algorithm_selection: Optional[AlgorithmSelection] = field(default=None, init=False)
  encryption_in: Optional[Encryption] = field(default=None, init=False)
  encryption_out: Optional[Encryption] = field(default=None, init=False)
  host_key: Optional[HostKey] = field(default=None, init=False)
  integrity_verification_in: Optional[IntegrityVerification] = field(default=None, init=False)
  integrity_verification_out: Optional[IntegrityVerification] = field(default=None, init=False)

  sequence_number_in: int = field(default=0, init=False)
  sequence_number_out: int = field(default=0, init=False)
  session_id: Optional[bytes] = None

  key_exchange_flow: Optional[MessageFlow] = None
  user_auth_flow: Optional[MessageFlow] = None


  async def read(self, byte_count: int, /):
    data = bytes()

    while len(data) < byte_count:
      chunk = await self.reader.read(byte_count - len(data))

      if not chunk:
        raise ConnectionClosedError

      data += chunk

    return data


  async def read_message(self):
    # Read packet length or first block

    if self.encryption_in is not None:
      sized_packet = self.encryption_in.decrypt_blocks(await self.read(self.encryption_in.block_size()))
    else:
      sized_packet = await self.read(4)


    # Read rest of packet
    # See: RFC 4253 Section 6

    packet_length_bytes = sized_packet[:4]
    packet_length = struct.unpack('>I', packet_length_bytes)[0]

    if self.encryption_in is not None:
      missing_block_count = (packet_length + 4) // self.encryption_in.block_size() - 1
      sized_packet += self.encryption_in.decrypt_blocks(await self.read(self.encryption_in.block_size() * missing_block_count))
      packet = sized_packet[4:]
    else:
      packet = await self.read(packet_length)
      sized_packet += packet

    padding_length = packet[0]
    payload_length = packet_length - padding_length - 1

    payload = packet[1:(1 + payload_length)]

    # TODO: Checks on lengths


    # Verify integrity using MAC
    # See: RFC 4253 Section 6.4

    if self.integrity_verification_in is not None:
      expected_digest = await self.read(self.integrity_verification_in.digest_size())

      produced_digest = self.integrity_verification_in.produce(struct.pack('>I', self.sequence_number_in) + sized_packet)

      if expected_digest != produced_digest:
        raise ProtocolError('Integrity verification failure')


    # Return payload

    self.sequence_number_in += 1

    return payload

  def write_message(self, message: EncodableMessage):
    payload = message.encode_payload()
    sized_packet = encode_packet(payload, block_size=(self.encryption_out.block_size() if self.encryption_out else None))

    if self.encryption_out is not None:
      self.writer.write(self.encryption_out.encrypt_blocks(sized_packet))
    else:
      self.writer.write(sized_packet)

    if self.integrity_verification_out is not None:
      self.writer.write(self.integrity_verification_out.produce(struct.pack('>I', self.sequence_number_out) + sized_packet))

    self.sequence_number_out += 1

    # Return payload because the KexInit message payload is reused for key exchange
    return payload


  async def run_key_exchange(self):
    # Create key exchange flow

    self.key_exchange_flow = MessageFlow()
    read = self.key_exchange_flow.read


    # Send server KexInit message

    server_kex_init = KexInitMessage(
      kex_algorithms=['diffie-hellman-group-exchange-sha256'],
      server_host_key_algorithms=list(set(key.algorithm() for key in self.server.host_keys)),
      encryption_algorithms_client_to_server=['aes128-ctr'],
      encryption_algorithms_server_to_client=['aes256-ctr'],
      mac_algorithms_client_to_server=['hmac-sha2-256'],
      mac_algorithms_server_to_client=['hmac-sha1'],
      compression_algorithms_client_to_server=['none'],
      compression_algorithms_server_to_client=['none'],
      languages_client_to_server=[],
      languages_server_to_client=[],
      first_kex_packet_follows=False
    )

    server_kex_init_payload = self.write_message(server_kex_init)


    # Read client KexInit message

    # if client_key_exchange:
    #   client_kex_init, client_kex_init_payload = client_key_exchange
    # else:

    client_kex_init, client_kex_init_payload = await read(KexInitMessage)


    # Negotiate algorithms

    self.algorithm_selection = negotiate_algorithms(
      client_kex_init,
      server_kex_init
    )

    self.host_key = next(key for key in self.server.host_keys if key.algorithm() == self.algorithm_selection.server_host_key_algorithm)


    # Run key exchange

    CurrentKeyExchange = resolve_key_exchange(self.algorithm_selection.kex_algorithm)

    key_exchange = CurrentKeyExchange()
    exchange_hash, shared_key = await key_exchange.run(self, read, client_kex_init_payload, server_kex_init_payload)


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
      iv=derive_key(b'B', EncryptionOut.block_size())
    )

    IntegrityVerificationOut = resolve_integrity_verification(self.algorithm_selection.mac_algorithm_server_to_client)

    self.integrity_verification_out = IntegrityVerificationOut(
      key=derive_key(b'F', IntegrityVerificationOut.key_size())
    )


    # Establish input algorithms

    await read(NewKeysMessage)

    EncryptionIn = resolve_encryption(self.algorithm_selection.encryption_algorithm_client_to_server)

    self.encryption_in = EncryptionIn(
      key=derive_key(b'C', EncryptionIn.key_size()),
      iv=derive_key(b'A', EncryptionIn.block_size())
    )

    IntegrityVerificationIn = resolve_integrity_verification(self.algorithm_selection.mac_algorithm_client_to_server)

    self.integrity_verification_in = IntegrityVerificationIn(
      key=derive_key(b'E', IntegrityVerificationIn.key_size())
    )


    # Finish flow

    self.key_exchange_flow = None


  async def start_user_auth(self):
    self.user_auth_flow = MessageFlow()

    try:
      await run_user_auth(self, self.user_auth_flow.read)
    finally:
      self.user_auth_flow = None


  async def handle(self):
    try:
      # Send server ident string

      self.server_ident_string = IdentString(
        comment=None,
        software_version=self.server.software_version
      )

      self.writer.write(bytes(self.server_ident_string) + b'\r\n')


      # Read client ident string

      client_ident_string_terminated = await self.reader.readuntil(b'\r\n')

      if len(client_ident_string_terminated) > 0xff:
        raise ProtocolError

      self.client_ident_string = IdentString.decode(client_ident_string_terminated[:-2])


      # Listen for messages

      async with Pool.open() as pool:
        pool.spawn(prime(self.run_key_exchange()), name='key_exchange')

        while True:
          message_payload = await self.read_message()

          # See: RFC 4250 Section 4.1

          match (message_id := message_payload[0]):
            case KexInitMessage.id:
              if self.key_exchange_flow is None:
                pool.spawn(prime(self.run_key_exchange()))

              assert self.key_exchange_flow is not None
              await self.key_exchange_flow.feed(message_id, message_payload)

            case _ if (message_id == NewKeysMessage.id) or (30 <= message_id <= 49):
              if self.key_exchange_flow is None:
                raise ProtocolError

              await self.key_exchange_flow.feed(message_id, message_payload)

            case ServiceRequestMessage.id:
              if self.key_exchange_flow is not None:
                raise ProtocolError

              message_payload_io = ReadableBytesIOImpl(message_payload[1:])
              service_request = ServiceRequestMessage.decode(message_payload_io)

              match service_request.service_name:
                case 'ssh-userauth':
                  self.write_message(ServiceAcceptMessage(service_name=service_request.service_name))
                case _:
                  # TODO: Send correct error message
                  raise ProtocolError(f'Unsupported service name: {service_request.service_name!r}')

            case UserAuthRequestMessage.id:
              if self.user_auth_flow is not None:
                raise ProtocolError

              pool.spawn(prime(self.start_user_auth()), name='user_auth')

              assert self.user_auth_flow is not None
              await self.user_auth_flow.feed(message_id, message_payload)

            case ChannelOpenMessage.id:
              msg = ChannelOpenMessage.decode(ReadableBytesIOImpl(message_payload[1:]))

              if isinstance(msg, ChannelOpenUnknownMessage):
                self.write_message(ChannelOpenFailureMessage(
                  recipient_channel_id=msg.sender_channel_id,
                  reason_code=ChannelOpenFailureReason.UnknownChannelType,
                  description='Unknown channel type',
                  language_tag='en'
                ))
              else:
                self.write_message(ChannelOpenConfirmationMessage(ChannelOpenMessage(
                  max_packet_size=msg.max_packet_size,
                  sender_channel_id=msg.sender_channel_id,
                  window_size=msg.window_size
                ), recipient_channel_id=0))

            case ChannelRequestMessage.id:
              msg = ChannelRequestMessage.decode(ReadableBytesIOImpl(message_payload[1:]))
              pprint(msg)

            case _:
              raise ProtocolError(f'Unknown message id {message_id}')

    except ProtocolError as e:
      # print(e)
      # TODO: Send SSH_DISCONNECT_PROTOCOL_ERROR
      raise
    except ConnectionClosedError:
      pass
    finally:
      self.writer.close()
