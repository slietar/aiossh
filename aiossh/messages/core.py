from dataclasses import dataclass
from enum import IntEnum
from typing import ClassVar

from ..encoding import Codable
from .base import Message
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
