from abc import ABC, abstractmethod
from typing import ClassVar, Self

from ..util import ReadableBytesIO


class DecodableMessage(ABC):
  id: ClassVar[int]

  @classmethod
  @abstractmethod
  def decode(cls, reader: ReadableBytesIO) -> Self:
    ...


class EncodableMessage(ABC):
  id: ClassVar[int]

  @abstractmethod
  def encode(self) -> bytes:
    ...

  def encode_payload(self):
    return bytes([self.id]) + self.encode()
