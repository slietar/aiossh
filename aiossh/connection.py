import struct
from asyncio import StreamReader, StreamWriter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from .error import ProtocolError
from .key_exchange.dh import run_kex_dh
from .messages.base import EncodableMessage
from .messages.kex_dh_gex import (KexDhGexGroupMessage, KexDhGexInitMessage,
                                  KexDhGexReplyMessage, KexDhGexRequestMessage)
from .messages.kex_init import KexInitMessage
from .packet import encode_packet
from .util import ReadableBytesIOImpl

if TYPE_CHECKING:
  from .server import Server


SSH_PROTOCOL_VERSION = '2.0'


message_classes = [
  KexInitMessage,

  KexDhGexRequestMessage,
  KexDhGexGroupMessage,
  KexDhGexInitMessage,
  KexDhGexReplyMessage
]


# @dataclass(frozen=True, kw_only=True, slots=True)
# class AlgorithmAvailability:
#   kex_algorithms: list[str] = ['diffie-hellman-group-exchange-sha256']
#   server_host_key_algorithms: list[str] = ['ssh-ed25519']
#   encryption_algorithms_client_to_server: list[str] = []
#   encryption_algorithms_server_to_client: list[str] = []
#   mac_algorithms_client_to_server: list[str] = []
#   mac_algorithms_server_to_client: list[str] = []
#   compression_algorithms_client_to_server: list[str] = ['none']
#   compression_algorithms_server_to_client: list[str] = ['none']
#   languages_client_to_server: list[str] = []
#   languages_server_to_client: list[str] = []

@dataclass(frozen=True, kw_only=True, slots=True)
class AlgorithmSelection:
  kex_algorithm: str
  # mac_algorithm_client_to_server: str
  server_host_key_algorithm: str


def negotiate_algorithms(client: KexInitMessage, server: KexInitMessage):
  # See: RFC 4253 Section 7.1

  kex_algorithm = next((algorithm for algorithm in client.kex_algorithms if algorithm in server.kex_algorithms), None)
  server_host_key_algorithm = next((algorithm for algorithm in client.server_host_key_algorithms if algorithm in server.server_host_key_algorithms), None)

  if (kex_algorithm is None) or (server_host_key_algorithm is None):
    raise ProtocolError('Algorithm negotiation failure')

  return AlgorithmSelection(
    kex_algorithm=kex_algorithm,
    server_host_key_algorithm=server_host_key_algorithm
  )


@dataclass(slots=True)
class Connection:
  server: 'Server'

  reader: StreamReader
  writer: StreamWriter

  algorithm_selection: Optional[AlgorithmSelection] = field(default=None, init=False)


  async def read(self, byte_count: int, /):
    data = bytes()

    while len(data) < byte_count:
      chunk = await self.reader.read(byte_count - len(data))

      if not chunk:
        raise ProtocolError(f'Expected {byte_count} bytes')

      data += chunk

    return data


  async def read_message(self):
    # See: RFC 4253 Section 6

    packet_length = struct.unpack('>I', await self.read(4))[0]
    packet = await self.read(packet_length)

    padding_length = packet[0]
    payload_length = packet_length - padding_length - 1

    payload = packet[1:(1 + payload_length)]
    payload_io = ReadableBytesIOImpl(payload[1:])

    # TODO: Checks on lengths

    message_type = payload[0]

    for message_class in message_classes:
      if message_class.id == message_type:
        return message_class.decode(payload_io)

    raise ProtocolError(f'Unknown packet type {message_type}')

    # TODO: Possibly read MAC

  def write_message(self, message: EncodableMessage):
    self.writer.write(encode_packet(bytes([message.id]) + message.encode()))
    # self.writer.write(encode_packet(message.encode_payload()))


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
        mac_algorithms_client_to_server=['hmac-sha2-256'],
        mac_algorithms_server_to_client=['hmac-sha2-256'],
        compression_algorithms_client_to_server=['none'],
        compression_algorithms_server_to_client=['none'],
        languages_client_to_server=[],
        languages_server_to_client=[],
        first_kex_packet_follows=False
      )

      self.write_message(server_kex_init)


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

      print(f'{comments=}')
      print(f'{software_version=}')


      # Decode kexinit

      client_kex_init = await self.read_message()

      if not isinstance(client_kex_init, KexInitMessage):
        raise ProtocolError('Expected Kex packet')

      self.algorithm_selection = negotiate_algorithms(client_kex_init, server_kex_init)

      # from pprint import pprint
      # pprint(client_kex_init)


      # Run key exchange

      match self.algorithm_selection.kex_algorithm:
        case 'diffie-hellman-group-exchange-sha256':
          await run_kex_dh(
            self,
            client_ident_string,
            server_ident_string,
            client_kex_init,
            server_kex_init
          )
        case _:
          raise Exception('Unreachable')



    finally:
      self.writer.close()
