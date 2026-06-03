from abc import ABC, abstractmethod
from typing import ClassVar, Self, override

from ..encoding import AutoCodable
from ..reader import Reader


class Message(ABC):
  id: ClassVar[int]

  @abstractmethod
  def encode_payload(self) -> bytes:
    ...

  @classmethod
  @abstractmethod
  def decode_payload(cls, payload: bytes) -> Self:
    ...


class AutoCodableMessage(AutoCodable, Message):
  @override
  def encode_payload(self):
    return bytes([self.id]) + self.encode()

  @override
  @classmethod
  def decode_payload(cls, payload: bytes) -> Self:
    assert payload[0] == cls.id

    with Reader(payload[1:]) as reader:
      return cls.decode(reader)
