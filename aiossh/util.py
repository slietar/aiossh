from dataclasses import dataclass, field
from typing import Protocol

from .error import ProtocolError


class ReadableBytesIO(Protocol):
  def read(self, byte_count: int, /) -> bytes:
    ...

@dataclass(slots=True)
class ReadableBytesIOImpl:
  data: bytes
  position: int = field(default=0, init=False)

  def read(self, byte_count: int, /):
    if self.position + byte_count > len(self.data):
      raise ProtocolError(f'Expected {byte_count} bytes, found {len(self.data) - self.position}')

    view = self.data[self.position:(self.position + byte_count)]
    self.position += byte_count

    return view
