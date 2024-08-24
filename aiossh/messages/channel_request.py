from dataclasses import dataclass
from typing import Annotated, ClassVar

from ..encoding import Codable, Name, UnionAnnotation
from .base import DecodableMessage, EncodableMessage


@dataclass(kw_only=True, slots=True)
class ChannelRequestDetailsEnv(Codable):
  # Section 6.4

  key: ClassVar[str] = 'env'

  name: bytes
  value: bytes


@dataclass(kw_only=True, slots=True)
class ChannelRequestDetailsPtyReq(Codable):
  # Section 6.2

  key: ClassVar[str] = 'pty-req'

  term_name: bytes
  term_width_chars: int
  term_height_chars: int
  term_width_pixels: int
  term_height_pixels: int
  term_modes: bytes


@dataclass(kw_only=True, slots=True)
class ChannelRequestMessage(Codable, DecodableMessage):
  id: ClassVar[int] = 98

  recipient_channel_id: int
  request_type: Name
  want_reply: bool

  details: Annotated[ChannelRequestDetailsEnv | ChannelRequestDetailsPtyReq | None, UnionAnnotation('request_type', 'key')]


@dataclass(kw_only=True, slots=True)
class ChannelSuccessMessage(Codable, EncodableMessage):
  id: ClassVar[int] = 99

  recipient_channel_id: int


@dataclass(kw_only=True, slots=True)
class ChannelFailureMessage(Codable, EncodableMessage):
  id: ClassVar[int] = 100

  recipient_channel_id: int
