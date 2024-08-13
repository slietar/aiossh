from dataclasses import dataclass
from typing import ClassVar

from ..util import ReadableBytesIO
from .base import EncodableMessage


@dataclass(frozen=True, kw_only=True, slots=True)
class NewKeysMessage(EncodableMessage):
  id: ClassVar[int] = 21

  def encode(self):
    return b''

  @classmethod
  def decode(cls, reader: ReadableBytesIO):
    return cls()
