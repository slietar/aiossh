from typing import ClassVar, Self

from ..encoding import AutoCodable, CodableABC
from ..reader import Reader


class Message(CodableABC):
  id: ClassVar[int]

  def encode_payload(self):
    return bytes([self.id]) + self.encode()

  @classmethod
  def decode_payload(cls, payload: bytes) -> Self:
    assert payload[0] == cls.id

    with Reader(payload[1:]) as reader:
      return cls.decode(reader)


class AutoCodableMessage(AutoCodable, Message):
  pass
