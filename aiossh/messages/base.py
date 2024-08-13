from abc import ABC, abstractmethod
from typing import ClassVar


class EncodableMessage(ABC):
  id: ClassVar[int]

  @abstractmethod
  def encode(self) -> bytes:
    ...

  def encode_payload(self):
    return bytes([self.id]) + self.encode()
