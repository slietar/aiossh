from dataclasses import dataclass
from typing import ClassVar

from ..structures.primitives import decode_name, encode_name
from ..util import ReadableBytesIO
from .base import DecodableMessage, EncodableMessage


@dataclass(frozen=True, kw_only=True, slots=True)
class NewKeysMessage(DecodableMessage, EncodableMessage):
  id: ClassVar[int] = 21

  def encode(self):
    return b''

  @classmethod
  def decode(cls, reader: ReadableBytesIO):
    return cls()


# See: RFC 4253 Section 10

@dataclass(frozen=True, kw_only=True, slots=True)
class ServiceRequestMessage(DecodableMessage):
  id: ClassVar[int] = 5

  service_name: str

  @classmethod
  def decode(cls, reader: ReadableBytesIO):
    return cls(service_name=decode_name(reader))


@dataclass(frozen=True, kw_only=True, slots=True)
class ServiceAcceptMessage(EncodableMessage):
  id: ClassVar[int] = 6

  service_name: str

  def encode(self):
    return encode_name(self.service_name)
