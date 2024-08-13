from pprint import pprint
import struct
from asyncio import StreamReader, StreamWriter
from dataclasses import dataclass

from .prime import find_prime, load_paths
from .messages.kex_dh_gex import KexDhGexGroupMessage, KexDhGexRequestMessage
from .packet import encode_packet
from .error import ProtocolError
from .messages.kex_init import KexInitMessage
from .util import ReadableBytesIOImpl

SSH_PROTOCOL_VERSION = '2.0'


primes = list(load_paths())


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


  async def read_message(self):
    packet_length = struct.unpack('>I', await self.read(4))[0]
    packet = await self.read(packet_length)

    padding_length = packet[0]
    payload_length = packet_length - padding_length - 1

    payload = packet[1:(1 + payload_length)]
    payload_io = ReadableBytesIOImpl(payload[1:])

    # TODO: Checks

    match payload[0]:
      case KexInitMessage.id:
        return KexInitMessage.decode(payload_io)
      case KexDhGexRequestMessage.id:
        return KexDhGexRequestMessage.decode(payload_io)
      case _:
        raise ProtocolError(f'Unknown packet type {payload[0]}')

    # TODO: Possibly read MAC

  def write_message(self, message):
    self.writer.write(encode_packet(bytes([message.id]) + message.encode()))


  async def handle(self):
    try:
      software_version = 'aiossh_0.0.0'

      self.writer.write(f'SSH-{SSH_PROTOCOL_VERSION}-{software_version}\r\n'.encode())

      server_kex_packet = KexInitMessage(
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

      self.write_message(server_kex_packet)


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

      client_kex_init = await self.read_message()

      if not isinstance(client_kex_init, KexInitMessage):
        raise ProtocolError('Expected Kex packet')

      kex_dh_gex_request = await self.read_message()
      assert isinstance(kex_dh_gex_request, KexDhGexRequestMessage)

      # TODO: Checks on request

      prime = find_prime(primes, kex_dh_gex_request.min, kex_dh_gex_request.n, kex_dh_gex_request.max)

      if prime:
        p = prime.value
        g = prime.generator
      else:
        from cryptography.hazmat.primitives.asymmetric import dh
        params = dh.generate_parameters(generator=2, key_size=kex_dh_gex_request.n).parameter_numbers()

        p = params.p
        g = params.g


      self.write_message(KexDhGexGroupMessage(p=p, g=g))

      print(await self.read_message())



      # q = (self.p - 1) // 2
      # qnorm = util.deflate_long(q, 0)
      # qhbyte = byte_ord(qnorm[0])
      # byte_count = len(qnorm)
      # qmask = 0xFF
      # while not (qhbyte & 0x80):
      #     qhbyte <<= 1
      #     qmask >>= 1
      # while True:
      #     x_bytes = os.urandom(byte_count)
      #     x_bytes = byte_mask(x_bytes[0], qmask) + x_bytes[1:]
      #     x = util.inflate_long(x_bytes, 1)
      #     if (x > 1) and (x < q):
      #         break
      # self.x = x


    finally:
      self.writer.close()
