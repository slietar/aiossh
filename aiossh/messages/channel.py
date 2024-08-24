from abc import ABC
from dataclasses import dataclass
from enum import IntEnum
from typing import ClassVar

from ..structures.primitives import (decode_name, decode_uint32, encode_name,
                                     encode_string, encode_text, encode_uint32)
from .base import DecodableMessage, EncodableMessage
from .types import LanguageTag


# See: RFC 4254

@dataclass(kw_only=True, slots=True)
class ChannelOpenMessage(DecodableMessage, ABC):
  # Section 5.1

  id: ClassVar[int] = 90

  max_packet_size: int
  sender_channel_id: int
  window_size: int

  def encode(self):
    return encode_uint32(self.sender_channel_id)\
      + encode_uint32(self.window_size)\
      + encode_uint32(self.max_packet_size)

  @classmethod
  def decode(cls, reader) -> 'ChannelOpenMessage':
    channel_type = decode_name(reader)

    kwargs = dict(
      sender_channel_id=decode_uint32(reader),
      window_size=decode_uint32(reader),
      max_packet_size=decode_uint32(reader)
    )

    match channel_type:
      case 'direct-tcpip':
        return ChannelOpenDirectTcpIpMessage(
          **kwargs,

          # Order matters
          recipient_address=decode_name(reader),
          recipient_port=decode_uint32(reader),
          originator_address=decode_name(reader),
          originator_port=decode_uint32(reader)
        )

      case 'forwarded-tcpip':
        return ChannelOpenForwardedTcpIpMessage(
          **kwargs,

          # Order matters
          recipient_address=decode_name(reader),
          recipient_port=decode_uint32(reader),
          originator_address=decode_name(reader),
          originator_port=decode_uint32(reader)
        )

      case 'session':
        return ChannelOpenSessionMessage(**kwargs)

      case 'x11':
        return ChannelOpenX11Message(
          **kwargs,

          # Order matters
          originator_address=decode_name(reader),
          originator_port=decode_uint32(reader)
        )

      case _:
        return ChannelOpenUnknownMessage(**kwargs)


@dataclass(slots=True)
class ChannelOpenSessionMessage(ChannelOpenMessage):
  # Section 6.1

  def encode(self):
    # Using super() with args because of a bug
    # See https://github.com/python/cpython/issues/90562
    return encode_name('session') + super(ChannelOpenSessionMessage, self).encode()


@dataclass(kw_only=True, slots=True)
class ChannelOpenDirectTcpIpMessage(ChannelOpenMessage):
  # Section 7.2

  originator_address: str
  originator_port: int
  recipient_address: str
  recipient_port: int

  def encode(self):
    return super().encode()\
      + encode_name('direct-tcpip')\
      + encode_name(self.recipient_address)\
      + encode_uint32(self.recipient_port)\
      + encode_name(self.originator_address)\
      + encode_uint32(self.originator_port)

@dataclass(kw_only=True, slots=True)
class ChannelOpenForwardedTcpIpMessage(ChannelOpenMessage):
  # Section 7.2

  originator_address: str
  originator_port: int
  recipient_address: str
  recipient_port: int

  def encode(self):
    return super().encode()\
      + encode_name('forwarded-tcpip')\
      + encode_name(self.recipient_address)\
      + encode_uint32(self.recipient_port)\
      + encode_name(self.originator_address)\
      + encode_uint32(self.originator_port)

@dataclass(kw_only=True, slots=True)
class ChannelOpenX11Message(ChannelOpenMessage):
  # Section 6.3.2

  originator_address: str
  originator_port: int

  def encode(self):
    return super().encode()\
      + encode_name('x11')\
      + encode_name(self.originator_address)\
      + encode_uint32(self.originator_port)

@dataclass(kw_only=True, slots=True)
class ChannelOpenUnknownMessage(ChannelOpenMessage):
  pass


@dataclass(slots=True)
class ChannelOpenConfirmationMessage(EncodableMessage):
  id: ClassVar[int] = 91

  inner: ChannelOpenMessage
  recipient_channel_id: int

  def encode(self):
    return encode_uint32(self.recipient_channel_id) + self.inner.encode()


class ChannelOpenFailureReason(IntEnum):
  AdministrativelyProhibited = 1
  ConnectFailed = 2
  UnknownChannelType = 3
  ResourceShortage = 4


@dataclass(kw_only=True, slots=True)
class ChannelOpenFailureMessage(EncodableMessage):
  id: ClassVar[int] = 92

  recipient_channel_id: int
  reason_code: int # Using int instead of ChannelOpenFailureReason as there can be custom codes
  description: str
  language_tag: LanguageTag

  def encode(self):
    return encode_uint32(self.recipient_channel_id)\
      + encode_uint32(self.reason_code)\
      + encode_text(self.description)\
      + encode_name(self.language_tag)
