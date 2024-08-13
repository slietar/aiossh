import asyncio
from asyncio import StreamReader, StreamWriter
from dataclasses import dataclass, field
from io import BytesIO
import math
import os
from pprint import pprint
import signal
import struct
from typing import IO


SSH_PROTOCOL_VERSION = '2.0'

class Constants:
  SSH_MSG_KEXINIT = 20


class ProtocolError(Exception):
  pass


@dataclass(slots=True)
class ReadableBytesIO:
  data: bytes
  position: int = field(default=0, init=False)

  def read(self, byte_count: int, /):
    if self.position + byte_count > len(self.data):
      raise ProtocolError(f'Expected {byte_count} bytes')

    view = self.data[self.position:(self.position + byte_count)]
    self.position += byte_count

    return view



@dataclass(frozen=True, kw_only=True, slots=True)
class KexPacket:
  kex_algorithms: list[str]
  server_host_key_algorithms: list[str]
  encryption_algorithms_client_to_server: list[str]
  encryption_algorithms_server_to_client: list[str]
  mac_algorithms_client_to_server: list[str]
  mac_algorithms_server_to_client: list[str]
  compression_algorithms_client_to_server: list[str]
  compression_algorithms_server_to_client: list[str]
  languages_client_to_server: list[str]
  languages_server_to_client: list[str]
  first_kex_packet_follows: bool

  def encode(self):
    return os.urandom(16)\
      + encore_name_list(self.kex_algorithms)\
      + encore_name_list(self.server_host_key_algorithms)\
      + encore_name_list(self.encryption_algorithms_client_to_server)\
      + encore_name_list(self.encryption_algorithms_server_to_client)\
      + encore_name_list(self.mac_algorithms_client_to_server)\
      + encore_name_list(self.mac_algorithms_server_to_client)\
      + encore_name_list(self.compression_algorithms_client_to_server)\
      + encore_name_list(self.compression_algorithms_server_to_client)\
      + encore_name_list(self.languages_client_to_server)\
      + encore_name_list(self.languages_server_to_client)\
      + struct.pack('>?I', False, 0)


  @classmethod
  def decode(cls, file: ReadableBytesIO):
    file.read(16)

    return cls(
      kex_algorithms=decode_name_list(file),
      server_host_key_algorithms=decode_name_list(file),
      encryption_algorithms_client_to_server=decode_name_list(file),
      encryption_algorithms_server_to_client=decode_name_list(file),
      mac_algorithms_client_to_server=decode_name_list(file),
      mac_algorithms_server_to_client=decode_name_list(file),
      compression_algorithms_client_to_server=decode_name_list(file),
      compression_algorithms_server_to_client=decode_name_list(file),
      languages_client_to_server=decode_name_list(file),
      languages_server_to_client=decode_name_list(file),
      first_kex_packet_follows=struct.unpack('>?', file.read(1))[0]
    )


print('PID', os.getpid())

async def serve():
  async def handle_connection_sync(reader: StreamReader, writer: StreamWriter):
    try:
      software_version = 'aiossh_0.0.0'

      writer.write(f'SSH-{SSH_PROTOCOL_VERSION}-{software_version}\r\n'.encode())

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

      writer.write(encode_packet(bytes([Constants.SSH_MSG_KEXINIT]) + p.encode()))


      # Decode first line

      first_line = await reader.readuntil(b'\r\n')

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

      packet = await decode_packet(reader)

      pprint(packet)


    finally:
      writer.close()

    # while True:
    #   if not message:
    #     return

    #   print('msg', message)

  server = await asyncio.start_server(
    handle_connection_sync,
    ['127.0.0.1'],
    port=1302
  )

  await server.serve_forever()


async def main():
  task = asyncio.create_task(serve())

  loop = asyncio.get_event_loop()

  for sig in [signal.SIGINT, signal.SIGTERM]:
    loop.add_signal_handler(sig, task.cancel)

  try:
    await task
  except asyncio.CancelledError:
    pass



def encore_name_list(names: list[str], /):
  encoded = ','.join(names).encode('ascii')
  return struct.pack('>I', len(encoded)) + encoded

def decode_name_list(file: ReadableBytesIO):
  length: int = struct.unpack('>I', file.read(4))[0]
  data = file.read(length)

  if len(data) != length:
    raise ProtocolError

  try:
    decoded = data.decode('ascii')
  except UnicodeDecodeError as e:
    raise ProtocolError from e

  return decoded.split(',')


# print(encore_name_list([]).hex())
# print(encore_name_list(['zlib']).hex())
# print(encore_name_list(['zlib', 'none']).hex())


MIN_PADDING = 4

def encode_packet(payload: bytes):
  padding_length = 0

  len_base = len(payload) + 5
  len_min_padded = len_base + MIN_PADDING
  len_padded = math.ceil(len_min_padded / 8) * 8

  padding_length = len_padded - len_min_padded + MIN_PADDING

  assert (len_base + padding_length) % 8 == 0
  assert 4 <= padding_length <= 0xff

  packet = struct.pack('>B', padding_length) + payload + os.urandom(padding_length)
  return struct.pack('>I', len(packet)) + packet

  # print(f'{len_min_padded=}')
  # print(f'{len_padded=}')
  # print(f'{padding_length=}')
  # print(len(payload) + 5 + padding_length)

# print(encode_packet(b'foo').hex(' '))


async def read(reader: StreamReader, byte_count: int):
  data = bytes()

  while len(data) < byte_count:
    chunk = await reader.read(byte_count - len(data))

    if not chunk:
      raise ProtocolError(f'Expected {byte_count} bytes')

    data += chunk

  return data

# Returns the packet payload
async def decode_packet(reader: StreamReader):
  packet_length = struct.unpack('>I', await read(reader, 4))[0]
  packet = await read(reader, packet_length)

  padding_length = packet[0]
  payload_length = packet_length - padding_length - 1
  payload = packet[1:payload_length]

  # TODO: Checks

  match payload[0]:
    case Constants.SSH_MSG_KEXINIT:
      return KexPacket.decode(ReadableBytesIO(payload[1:]))
    case _:
      raise ProtocolError('Unknown packet type')

  # TODO: Possibly read MAC


asyncio.run(main())
