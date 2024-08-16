import struct
from dataclasses import dataclass
from typing import ClassVar

from .base import DecodableMessage, EncodableMessage

from ..structures.primitives import decode_mpint, encode_mpint, encode_string
from ..util import ReadableBytesIO


# Client-only

@dataclass(frozen=True, kw_only=True, slots=True)
class KexDhGexRequestMessage(DecodableMessage):
  id: ClassVar[int] = 34

  min: int
  n: int
  max: int

  @classmethod
  def decode(cls, reader: ReadableBytesIO):
    min, n, max = struct.unpack('>III', reader.read(12))

    return cls(
      min=min,
      n=n,
      max=max
    )


# Server-only

@dataclass(frozen=True, kw_only=True, slots=True)
class KexDhGexGroupMessage(EncodableMessage):
  id: ClassVar[int] = 31

  p: int
  g: int

  def encode(self):
    return encode_mpint(self.p) + encode_mpint(self.g)


# Client-only

@dataclass(frozen=True, kw_only=True, slots=True)
class KexDhGexInitMessage(DecodableMessage):
  id: ClassVar[int] = 32

  e: int

  @classmethod
  def decode(cls, reader: ReadableBytesIO):
    return cls(e=decode_mpint(reader))


# Server-only

@dataclass(frozen=True, kw_only=True, slots=True)
class KexDhGexReplyMessage(EncodableMessage):
  id: ClassVar[int] = 33

  host_key: bytes
  f: int
  signature: bytes

  def encode(self):
    return encode_string(self.host_key) + encode_mpint(self.f) + encode_string(self.signature)
