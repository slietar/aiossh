import struct

from .error import ProtocolError
from .util import ReadableBytesIO


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
