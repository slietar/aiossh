from abc import ABC, abstractmethod
from typing import ClassVar, Self

from ..encoding import CodableABC
from ..util import ReadableBytesIO


class DecodableMessage(ABC):
  """
  @deprecated
  """

  id: ClassVar[int]

  @classmethod
  @abstractmethod
  def decode(cls, reader: ReadableBytesIO) -> Self:
    ...


class EncodableMessage(ABC):
  """
  @deprecated
  """

  id: ClassVar[int]

  @abstractmethod
  def encode(self) -> bytes:
    ...

  def encode_payload(self):
    return bytes([self.id]) + self.encode()


class Message(CodableABC, DecodableMessage, EncodableMessage, ABC):
  id: ClassVar[int]

  def encode_payload(self):
    return bytes([self.id]) + self.encode()
