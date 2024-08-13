import hashlib
import struct
from asyncio import StreamReader, StreamWriter
from dataclasses import dataclass
from pprint import pprint

from cryptography.hazmat.primitives.asymmetric import dh, ed25519

from .error import ProtocolError
from .messages.kex_dh_gex import (KexDhGexGroupMessage, KexDhGexInitMessage,
                                  KexDhGexReplyMessage, KexDhGexRequestMessage)
from .messages.kex_init import KexInitMessage
from .packet import encode_packet
from .prime import find_prime, load_paths
from .structures import encode_ed25519_public_key, encode_mpint, encode_rsa_public_key
from .util import ReadableBytesIOImpl

SSH_PROTOCOL_VERSION = '2.0'


primes = list(load_paths())

message_classes = [
  KexInitMessage,

  KexDhGexRequestMessage,
  KexDhGexGroupMessage,
  KexDhGexInitMessage,
  KexDhGexReplyMessage
]


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

    # TODO: Checks on lengths

    message_type = payload[0]

    for message_class in message_classes:
      if message_class.id == message_type:
        return message_class.decode(payload_io)

    raise ProtocolError(f'Unknown packet type {message_type}')

    # TODO: Possibly read MAC

  def write_message(self, message):
    self.writer.write(encode_packet(bytes([message.id]) + message.encode()))
    # self.writer.write(encode_packet(message.encode_payload()))


  async def handle(self):
    try:
      software_version = 'aiossh_0.0.0'

      server_ident_string = f'SSH-{SSH_PROTOCOL_VERSION}-{software_version}'.encode()
      self.writer.write(server_ident_string + b'\r\n')

      server_kex_init = KexInitMessage(
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


      # Run key exchange

      kex_dh_gex_request = await self.read_message()
      assert isinstance(kex_dh_gex_request, KexDhGexRequestMessage)

      # TODO: Checks on min, n, max

      prime = find_prime(primes, kex_dh_gex_request.min, kex_dh_gex_request.n, kex_dh_gex_request.max)

      if prime:
        param_numbers = dh.DHParameterNumbers(p=prime.value, g=prime.generator)
      else:
        param_numbers = dh.generate_parameters(generator=2, key_size=kex_dh_gex_request.n).parameter_numbers()


      self.write_message(KexDhGexGroupMessage(p=param_numbers.p, g=param_numbers.g))

      kex_dh_init = await self.read_message()
      assert isinstance(kex_dh_init, KexDhGexInitMessage)


      server_private_key = param_numbers.parameters().generate_private_key()
      server_public_key = server_private_key.public_key()
      server_f = server_public_key.public_numbers().y

      client_public_key = dh.DHPublicNumbers(kex_dh_init.e, param_numbers).public_key()

      shared_key = server_private_key.exchange(client_public_key)

      # host_private_key = rsa.generate_private_key(
      #   public_exponent=65537,
      #   key_size=2048,
      # )

      # host_public_key = host_private_key.public_key()
      # encoded_host_public_key = encode_rsa_public_key(host_public_key)

      host_private_key = ed25519.Ed25519PrivateKey.generate()
      host_public_key = host_private_key.public_key()
      encoded_host_public_key = encode_ed25519_public_key(host_public_key)


      # print(f'{shared_key=}')

      xx =\
          client_ident_string\
        + server_ident_string\
        + client_kex_init.encode_payload()\
        + server_kex_init.encode_payload()\
        + encoded_host_public_key\
        + struct.pack('>III', kex_dh_gex_request.min, kex_dh_gex_request.n, kex_dh_gex_request.max)\
        + encode_mpint(param_numbers.p)\
        + encode_mpint(param_numbers.g)\
        + encode_mpint(kex_dh_init.e)\
        + encode_mpint(server_f)\
        + shared_key

      # print(xx.hex(' '))

      kex_dh_gex_reply = KexDhGexReplyMessage(
        host_key=encoded_host_public_key,
        f=server_f,
        signature=hashlib.sha256(xx).digest()
      )

      self.write_message(kex_dh_gex_reply)

    finally:
      self.writer.close()
