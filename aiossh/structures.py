import math
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from .error import ProtocolError
from .util import ReadableBytesIO, ReadableBytesIOImpl


def encore_name_list(names: list[str], /):
  encoded = ','.join(names).encode('ascii')
  return struct.pack('>I', len(encoded)) + encoded

def decode_name_list(reader: ReadableBytesIO):
  length: int = struct.unpack('>I', reader.read(4))[0]
  data = reader.read(length)

  if len(data) != length:
    raise ProtocolError

  try:
    decoded = data.decode('ascii')
  except UnicodeDecodeError as e:
    raise ProtocolError from e

  return decoded.split(',')


def encode_mpint(value: int, /):
  if value < 0:
    pos_value = (-value)
  else:
    pos_value = value

  byte_length = math.ceil((pos_value.bit_length() + 1) / 8) if pos_value != 0 else 0

  if value < 0:
    pos_value ^= (1 << (byte_length * 8)) - 1
    pos_value += 1

  return struct.pack('>I', byte_length) + pos_value.to_bytes(byte_length, byteorder='big')

def decode_mpint(reader: ReadableBytesIO):
  length: int = struct.unpack('>I', reader.read(4))[0]
  return int.from_bytes(reader.read(length), byteorder='big', signed=True)


def encode_string(value: bytes, /):
  return struct.pack('>I', len(value)) + value

def decode_string(reader: ReadableBytesIO):
  length: int = struct.unpack('>I', reader.read(4))[0]
  return reader.read(length)


def encode_ed25519_public_key(key: ed25519.Ed25519PublicKey, /):
  return encode_string(b'ssh-ed25519') + encode_string(key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
  ))

def encode_rsa_public_key(key: rsa.RSAPublicKey, /):
  numbers = key.public_numbers()
  return encode_string(b'ssh-rsa') + encode_mpint(numbers.e) + encode_mpint(numbers.n)


if __name__ == '__main__':
  for x in [0, 0x9a378f9b2e332a7, 0x80, -0x1234, -0xdeadbeef]:
    encoded = encode_mpint(x)
    print(f'{x: 26} {decode_mpint(ReadableBytesIOImpl(encoded)): 26} / {encoded.hex(' ')}')
