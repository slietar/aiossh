import struct
from dataclasses import dataclass
from typing import ClassVar

from ..util import ReadableBytesIO


# Client-only

@dataclass(frozen=True, kw_only=True, slots=True)
class KexDhGexRequestMessage:
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
class KexDhGexGroupMessage:
  id: ClassVar[int] = 31

  p: int
  g: int

  def encode(self):
    return struct.pack('>II', self.p, self.g)
