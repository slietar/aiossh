import math
import struct

from ..error import ProtocolError
from ..util import ReadableBytesIO, ReadableBytesIOImpl


# See: RFC 4251 Section 5

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
  byte_length = math.ceil((value.bit_length() + 1) / 8) if value != 0 else 0
  return struct.pack('>I', byte_length) + value.to_bytes(byte_length, byteorder='big', signed=True)

def decode_mpint(reader: ReadableBytesIO):
  length: int = struct.unpack('>I', reader.read(4))[0]
  return int.from_bytes(reader.read(length), byteorder='big', signed=True)


def encode_string(value: bytes, /):
  return struct.pack('>I', len(value)) + value

def decode_string(reader: ReadableBytesIO):
  length: int = struct.unpack('>I', reader.read(4))[0]
  return reader.read(length)


if __name__ == '__main__':
  for x in [0, 0x9a378f9b2e332a7, 0x80, -0x1234, -0xdeadbeef]:
    encoded = encode_mpint(x)
    print(f'{x: 26} {decode_mpint(ReadableBytesIOImpl(encoded)): 26} / {encoded.hex(' ')}')
