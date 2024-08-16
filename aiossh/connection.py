import hashlib
import math
import struct
from asyncio import StreamReader, StreamWriter
from dataclasses import dataclass, field
import sys
from typing import TYPE_CHECKING, Optional

from .integrity.hmac import HMACSHA1IntegrityVerification, HMACSHA256IntegrityVerification

from .encryption.aes import AESCTREncryption

from .error import ProtocolError
from .key_exchange.dh import run_kex_dh
from .messages.base import EncodableMessage
from .messages.kex_dh_gex import (KexDhGexGroupMessage, KexDhGexInitMessage,
                                  KexDhGexReplyMessage, KexDhGexRequestMessage)
from .messages.kex_init import KexInitMessage
from .messages.misc import NewKeysMessage
from .packet import encode_packet
from .structures.primitives import encode_mpint
from .util import ReadableBytesIOImpl

if TYPE_CHECKING:
  from .server import Server


SSH_PROTOCOL_VERSION = '2.0'


message_classes = [
  KexInitMessage,
  NewKeysMessage,

  KexDhGexRequestMessage,
  KexDhGexGroupMessage,
  KexDhGexInitMessage,
  KexDhGexReplyMessage
]


@dataclass(frozen=True, kw_only=True, slots=True)
class AlgorithmSelection:
  kex_algorithm: str
  server_host_key_algorithm: str
  mac_algorithm_client_to_server: str
  mac_algorithm_server_to_client: str


def negotiate_algorithms(client: KexInitMessage, server: KexInitMessage):
  # See: RFC 4253 Section 7.1

  kex_algorithm = next((algorithm for algorithm in client.kex_algorithms if algorithm in server.kex_algorithms), None)
  server_host_key_algorithm = next((algorithm for algorithm in client.server_host_key_algorithms if algorithm in server.server_host_key_algorithms), None)
  mac_algorithm_client_to_server = next((algorithm for algorithm in client.mac_algorithms_client_to_server if algorithm in server.mac_algorithms_client_to_server), None)
  mac_algorithm_server_to_client = next((algorithm for algorithm in client.mac_algorithms_server_to_client if algorithm in server.mac_algorithms_server_to_client), None)

  if (kex_algorithm is None) or (server_host_key_algorithm is None) or (mac_algorithm_client_to_server is None) or (mac_algorithm_server_to_client is None):
    raise ProtocolError('Algorithm negotiation failure')

  return AlgorithmSelection(
    kex_algorithm=kex_algorithm,
    server_host_key_algorithm=server_host_key_algorithm,
    mac_algorithm_client_to_server=mac_algorithm_client_to_server,
    mac_algorithm_server_to_client=mac_algorithm_server_to_client
  )


@dataclass(repr=False, slots=True)
class Connection:
  server: 'Server'

  reader: StreamReader
  writer: StreamWriter

  algorithm_selection: Optional[AlgorithmSelection] = field(default=None, init=False)
  encryption: Optional[AESCTREncryption] = field(default=None, init=False)
  integrity_verification: Optional[HMACSHA1IntegrityVerification] = field(default=None, init=False)

  sequence_number_client_to_server: int = field(default=0, init=False)
  sequence_number_server_to_client: int = field(default=0, init=False)
  session_id: Optional[bytes] = None

  # Buffer of decrypted data
  buffer: bytes = field(default=b'', init=False)


  async def read(self, byte_count: int, /):
    raise Exception
    if self.buffer:
      data = self.buffer[:byte_count]
      self.buffer = self.buffer[len(data):]

      missing_byte_count = byte_count - len(data)

      if missing_byte_count > 0:
        x = await self.read_unencrypted(missing_byte_count)
        print('Decrypt', x.hex())
        return data + self.encryption.decrypt(x)
      else:
        return data

    if self.encryption is not None:
      block_size = self.encryption.block_size()

      block_count = math.ceil(byte_count / block_size)

      for _ in range(block_count):
        x = await self.read_unencrypted(block_size)
        print('Decrypt', x.hex())

        self.buffer += self.encryption.decrypt(x)
        # self.buffer += self.encryption.decrypt(await self.read_unecrypted(block_size))

      data = self.buffer[:byte_count]
      self.buffer = self.buffer[byte_count:]
      return data
    else:
      return await self.read_unencrypted(byte_count)

  async def read_unencrypted(self, byte_count: int, /):
    data = bytes()

    while len(data) < byte_count:
      chunk = await self.reader.read(byte_count - len(data))

      if not chunk:
        raise ProtocolError(f'Expected {byte_count} bytes')

      data += chunk

    return data


  async def read_message(self):
    message, payload = await self.read_message_and_payload()
    return message

  async def read_message_and_payload(self):
    if self.encryption is not None:
      sized_packet = self.encryption.decrypt(await self.read_unencrypted(self.encryption.block_size()))
    else:
      sized_packet = await self.read_unencrypted(4)

    # See: RFC 4253 Section 6

    packet_length_bytes = sized_packet[:4]
    packet_length = struct.unpack('>I', packet_length_bytes)[0]

    if self.encryption is not None:
      missing_block_count = (packet_length + 4) // self.encryption.block_size() - 1
      sized_packet += self.encryption.decrypt(await self.read_unencrypted(self.encryption.block_size() * missing_block_count))
      packet = sized_packet[4:]
    else:
      packet = await self.read_unencrypted(packet_length)
      sized_packet += packet


    # packet_length_bytes = await self.read(4)
    # packet_length = struct.unpack('>I', packet_length_bytes)[0]
    # packet = await self.read(packet_length)
    print('Packet', (packet_length_bytes + packet).hex())
    # print(packet)
    # print('Packet length', len(packet), packet_length)

    padding_length = packet[0]
    payload_length = packet_length - padding_length - 1

    payload = packet[1:(1 + payload_length)]
    payload_io = ReadableBytesIOImpl(payload[1:])

    # TODO: Checks on lengths

    # See: RFC 4253 Section 6.4

    if self.integrity_verification is not None:
      digest = await self.read_unencrypted(self.integrity_verification.digest_size())
      # print('Digest', digest.hex())
      # print('Data', (struct.pack('>I', self.sequence_number_client_to_server) + packet_length_bytes + packet).hex())
      # print('Key', self.integrity_verification.key.hex())

      # x = self.integrity_verification.verify(struct.pack('>I', self.sequence_number_client_to_server) + packet_length_bytes + packet)
      x = self.integrity_verification.verify(struct.pack('>I', self.sequence_number_client_to_server) + sized_packet)
      # print(len(packet_length_bytes + packet))
      # print((packet_length_bytes + packet).hex(' '))
      print('>', digest.hex(' '))
      print('>', x.hex(' '))
      print()
      print(packet.hex(' '))

    self.sequence_number_client_to_server += 1

    message_type = payload[0]

    for message_class in message_classes:
      if message_class.id == message_type:
        return message_class.decode(payload_io), payload

    raise ProtocolError(f'Unknown packet type {message_type}')

  def write_message(self, message: EncodableMessage):
    self.writer.write(encode_packet(message.encode_payload()))


  async def handle(self):
    try:
      # See: RFC 4253 Section 4.2

      software_version = 'aiossh_0.0.0'

      server_ident_string = f'SSH-{SSH_PROTOCOL_VERSION}-{software_version}'.encode()
      self.writer.write(server_ident_string + b'\r\n')

      server_kex_init = KexInitMessage(
        kex_algorithms=['diffie-hellman-group-exchange-sha256'],
        server_host_key_algorithms=list(set(key.algorithm() for key in self.server.host_keys)),
        encryption_algorithms_client_to_server=['aes128-ctr'],
        encryption_algorithms_server_to_client=['aes128-ctr'],
        mac_algorithms_client_to_server=['hmac-sha1'],
        # mac_algorithms_client_to_server=['hmac-sha2-256'],
        mac_algorithms_server_to_client=['hmac-sha2-256'],
        compression_algorithms_client_to_server=['none'],
        compression_algorithms_server_to_client=['none'],
        languages_client_to_server=[],
        languages_server_to_client=[],
        first_kex_packet_follows=False
      )

      server_kex_init_payload = server_kex_init.encode_payload()
      self.writer.write(encode_packet(server_kex_init_payload))


      # Decode first line

      first_line = await self.reader.readuntil(b'\r\n')

      if len(first_line) > 0xff:
        raise ProtocolError

      client_ident_string = first_line[:-2]

      segments = client_ident_string.split(b' ', maxsplit=2)
      sub_segments = segments[0].split(b'-')

      if len(sub_segments) != 3:
        raise ProtocolError

      if sub_segments[0] != b'SSH':
        raise ProtocolError

      if sub_segments[1] != SSH_PROTOCOL_VERSION.encode():
        raise ProtocolError

      try:
        software_version = sub_segments[2].decode('ascii')
      except UnicodeDecodeError as e:
        raise ProtocolError from e

      if not software_version.isprintable():
        raise ProtocolError

      if len(segments) == 2:
        comments = segments[1]
      else:
        comments = None

      # print(f'{comments=}')
      # print(f'{software_version=}')


      # Decode kexinit

      client_kex_init, client_kex_init_payload = await self.read_message_and_payload()

      if not isinstance(client_kex_init, KexInitMessage):
        raise ProtocolError('Expected KexInit message')

      self.algorithm_selection = negotiate_algorithms(client_kex_init, server_kex_init)

      # from pprint import pprint
      # pprint(self.algorithm_selection)
      # pprint(client_kex_init)


      # Run key exchange

      match self.algorithm_selection.kex_algorithm:
        case 'diffie-hellman-group-exchange-sha256':
          exchange_hash, shared_key = await run_kex_dh(
            self,
            client_ident_string,
            server_ident_string,
            client_kex_init_payload,
            server_kex_init_payload
          )
        case _:
          raise Exception('Unreachable')


      # Compute key exchange output
      # See: RFC 4253 Section 7.2

      if self.session_id is None:
        self.session_id = exchange_hash

      encoded_shared_secret = encode_mpint(int.from_bytes(shared_key))

      # TODO: Use same algorithm as for key exchange
      def hash(x: bytes):
        return hashlib.sha256(x).digest()

      def derive(letter: bytes):
        assert self.session_id is not None
        return hash(encoded_shared_secret + exchange_hash + letter + self.session_id)

      # iv_client_to_server = derive(b'A')
      # iv_server_to_client = derive(b'B')
      # encryption_key_client_to_server = derive(b'C')
      # encryption_key_server_to_client = derive(b'D')
      # integrity_key_client_to_server = derive(b'E')
      # integrity_key_server_to_client = derive(b'F')

      def derive_n(letter: bytes, size: int):
        key = derive(letter)

        while len(key) < size:
          key += hash(encoded_shared_secret + exchange_hash + key)

        return key[:size]

      self.write_message(NewKeysMessage())
      assert isinstance(await self.read_message(), NewKeysMessage)


      # Do other stuff

      self.encryption = AESCTREncryption(
        key=derive_n(b'C', 16),
        iv=derive_n(b'A', 16)
      )

      print('Key', derive_n(b'C', 16).hex())
      print('IV', derive_n(b'A', 16).hex())

      # self.integrity_verification = HMACSHA256IntegrityVerification(
      self.integrity_verification = HMACSHA1IntegrityVerification(
        key=derive_n(b'E', HMACSHA1IntegrityVerification.key_size())
      )

      print(await self.read_message())

      # packet = bytes()

      # for _ in range(4):
      #   x = await self.read(16)
      #   packet += enc.decrypt(x)

      # def a():
      #   nonlocal packet

      #   packet_length = struct.unpack('>I', packet[:4])[0]
      #   packet = packet[4:]

      #   padding_length = packet[0]
      #   payload_length = packet_length - padding_length - 1

      #   payload = packet[1:(1 + payload_length)]
      #   payload_io = ReadableBytesIOImpl(payload[1:])

      #   # TODO: Checks on lengths

      #   message_type = payload[0]
      #   print(message_type)

      # print(packet.hex(' '))
      # a()

    finally:
      self.writer.close()
