from dataclasses import dataclass
from enum import IntEnum
from typing import ClassVar, override

from ..encoding import Codable
from ..error import ProtocolError
from ..structures.primitives import (
  decode_string,
  decode_text,
  decode_uint32,
  encode_text,
  encode_uint32,
)
from ..util import ReadableBytesIO
from .base import DecodableMessage, EncodableMessage, Message
from .types import LanguageTag


class DisconnectReason(IntEnum):
  HostNotAllowedToConnect = 1
  ProtocolError = 2
  KeyExchangeFailed = 3
  Reserved = 4
  MacError = 5
  CompressionError = 6
  ServiceNotAvailable = 7
  ProtocolVersionNotSupported = 8
  HostKeyNotVerifiable = 9
  ConnectionLost = 10
  ByApplication = 11
  TooManyConnections = 12
  AuthCancelledByUser = 13
  NoMoreAuthMethodsAvailable = 14
  IllegalUserName = 15


@dataclass(kw_only=True, slots=True)
class DisconnectMessage(Codable, Message):
  id: ClassVar[int] = 1

  reason_code: int
  description: str
  language_tag: LanguageTag


@dataclass(kw_only=True, slots=True)
class DebugMessage(Codable, Message):
  id: ClassVar[int] = 4

  always_display: bool
  message: str
  language_tag: LanguageTag


@dataclass(slots=True)
class UnimplementedMessage(Codable, Message):
  id: ClassVar[int] = 3

  sequence_number: int


@dataclass(slots=True)
class NewKeysMessage(Codable, Message):
  id: ClassVar[int] = 21


@dataclass(kw_only=True, slots=True)
class ExtInfoMessage(DecodableMessage, EncodableMessage):
  id: ClassVar[int] = 7

  extensions: dict[str, bytes]

  @override
  def encode(self):
    return encode_uint32(len(self.extensions)) + b''.join(
      encode_text(name) + value for name, value in self.extensions.items()
    )

  @classmethod
  @override
  def decode(cls, reader: ReadableBytesIO):
    extension_count = decode_uint32(reader)
    extensions = dict[str, bytes]()

    for _ in range(extension_count):
      name = decode_text(reader)
      value = decode_string(reader)

      if name in extensions:
        raise ProtocolError

      extensions[name] = value

    return cls(extensions=extensions)
