import math
import struct
from collections.abc import Sequence
from typing import Optional

from ..error import ProtocolError
from ..reader import Readable, Reader


# See: RFC 4251 Section 5

def encode_name_list(names: Sequence[str], /):
  encoded = ','.join(names).encode('ascii')
  return struct.pack('>I', len(encoded)) + encoded

def decode_name_list(reader: Readable):
  length: int = struct.unpack('>I', reader.read(4))[0]
  data = reader.read(length)

  if len(data) != length:
    raise ProtocolError

  try:
    decoded = data.decode('ascii')
  except UnicodeDecodeError as e:
    raise ProtocolError from e

  return decoded.split(',')


def encode_boolean(value: bool, /):
  return b'\x01' if value else b'\x00'

def decode_boolean(reader: Readable):
  return reader.read(1)[0] != 0x00


def encode_mpint(value: int, /):
  byte_length = math.ceil((value.bit_length() + 1) / 8) if value != 0 else 0
  return struct.pack('>I', byte_length) + value.to_bytes(byte_length, byteorder='big', signed=True)

def decode_mpint(reader: Readable):
  length: int = struct.unpack('>I', reader.read(4))[0]
  return int.from_bytes(reader.read(length), byteorder='big', signed=True)


def encode_string(value: bytes, /):
  return struct.pack('>I', len(value)) + value

def decode_string(reader: Readable, *, size: Optional[int] = None):
  length: int = struct.unpack('>I', reader.read(4))[0]

  if (size is not None) and (length != size):
    raise ProtocolError

  return reader.read(length)


def encode_name(value: str):
  return encode_string(value.encode('ascii'))

def decode_name(reader: Readable):
  data = decode_string(reader)

  try:
    return data.decode('ascii')
  except UnicodeDecodeError as e:
    raise ProtocolError from e


def encode_text(value: str, /):
  return encode_string(value.encode())

def decode_text(reader: Readable):
  data = decode_string(reader)

  try:
    return data.decode()
  except UnicodeDecodeError as e:
    raise ProtocolError from e


def encode_uint32(value: int, /):
  return struct.pack('>I', value)

def decode_uint32(reader: Readable) -> int:
  return struct.unpack('>I', reader.read(4))[0]


def encode_uint64(value: int, /):
  return struct.pack('>Q', value)


if __name__ == '__main__':
  for x in [0, 0x9a378f9b2e332a7, 0x80, -0x1234, -0xdeadbeef]:
    encoded = encode_mpint(x)
    print(f'{x: 26} {decode_mpint(Reader(encoded)): 26} / {encoded.hex(' ')}')
