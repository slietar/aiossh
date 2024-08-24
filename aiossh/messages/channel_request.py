from dataclasses import dataclass
from typing import Annotated, ClassVar, Literal, override

from ..encoding import Codable, Name

from ..structures.primitives import decode_name, decode_uint32, encode_uint32
from .base import DecodableMessage, EncodableMessage


@dataclass(kw_only=True, slots=True)
class ChannelRequestMessage(Codable, DecodableMessage):
  id: ClassVar[int] = 98

  recipient_channel_id: int
  request_type: Name
  want_reply: bool


# # Section 6.2

# @dataclass(kw_only=True, slots=True)
# class ChannelRequestPtyReq()


@dataclass(kw_only=True, slots=True)
class ChannelSuccessMessage(Codable, EncodableMessage):
  id: ClassVar[int] = 99

  recipient_channel_id: int


@dataclass(kw_only=True, slots=True)
class ChannelFailureMessage(Codable, EncodableMessage):
  id: ClassVar[int] = 100

  recipient_channel_id: int
