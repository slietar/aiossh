from pprint import pprint
import struct
from asyncio import StreamReader, StreamWriter
from dataclasses import dataclass

from .packet import encode_packet

from .error import ProtocolError
from .packets.kex import KexPacket
from .util import ReadableBytesIOImpl

SSH_PROTOCOL_VERSION = '2.0'


@dataclass(frozen=True, slots=True)
class Connection:
  reader: StreamReader
  writer: StreamWriter

  async def read(self, byte_count: int, /):
    data = bytes()

    while len(data) < byte_count:
      chunk = await self.reader.read(byte_count - len(data))

      if not chunk:
        raise ProtocolError(f'Expected {byte_count} bytes')

      data += chunk

    return data


  # Returns the packet payload
  async def decode_packet(self):
    packet_length = struct.unpack('>I', await self.read(4))[0]
    packet = await self.read(packet_length)

    padding_length = packet[0]
    payload_length = packet_length - padding_length - 1
    payload = packet[1:payload_length]
    payload_io = ReadableBytesIOImpl(payload[1:])

    # TODO: Checks

    match payload[0]:
      case KexPacket.id:
        return KexPacket.decode(payload_io)
      case _:
        raise ProtocolError('Unknown packet type')

    # TODO: Possibly read MAC


  async def handle(self):
    try:
      software_version = 'aiossh_0.0.0'

      self.writer.write(f'SSH-{SSH_PROTOCOL_VERSION}-{software_version}\r\n'.encode())

      kex_algorithms = [
        'diffie-hellman-group-exchange-sha256'
      ]

      p = KexPacket(
        kex_algorithms=['diffie-hellman-group-exchange-sha256'],
        server_host_key_algorithms=['ssh-ed25519'],
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

      self.writer.write(encode_packet(bytes([KexPacket.id]) + p.encode()))


      # Decode first line

      first_line = await self.reader.readuntil(b'\r\n')

      if len(first_line) > 0xff:
        raise ProtocolError

      segments = first_line[:-2].split(b' ', maxsplit=2)
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

      packet = await self.decode_packet()

      pprint(packet)


    finally:
      self.writer.close()
