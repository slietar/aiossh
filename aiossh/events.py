from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from .messages.channel import ChannelOpenFailureReason, ChannelOpenMessage


@dataclass(slots=True)
class AuthWithPasswordRequestEvent:
  user_name: str
  password: str
  respond: Callable[[bool], None]

@dataclass(slots=True)
class AuthWithPublicKeyRequestEvent:
  user_name: str
  algorithm: str
  public_key: bytes
  authenticating: bool
  respond: Callable[[bool], None]

@dataclass(slots=True)
class DataEvent:
  chunk: bytes

@dataclass(slots=True)
class ExchangedKeysEvent:
  pass


class OpenChannelEventAccept(Protocol):
  def __call__(self) -> int:
    ...

class OpenChannelEventReject(Protocol):
  def __call__(self, reason: ChannelOpenFailureReason, description: str) -> None:
    ...

@dataclass(slots=True)
class ChannelOpenEvent:
  message: ChannelOpenMessage

  accept: OpenChannelEventAccept
  reject: OpenChannelEventReject


@dataclass(slots=True)
class ChannelDataEvent:
  channel_id: int
  chunk: bytes

@dataclass(slots=True)
class ChannelEofEvent:
  channel_id: int


@dataclass(slots=True)
class SessionSetEnvEvent:
  name: str
  value: str

@dataclass(slots=True)
class SessionExecEvent:
  command: str
  accept: Callable[[], Stream]
  reject: Callable[[], None]

@dataclass(slots=True)
class SessionShellEvent:
  accept: Callable[[], Stream]
  reject: Callable[[], None]


@dataclass(slots=True)
class Stream:
    exit: Callable[[int], None]
    write: Callable[[bytes], None]


type Event = (
    AuthWithPasswordRequestEvent
    | AuthWithPublicKeyRequestEvent
    | DataEvent
    | ExchangedKeysEvent
    | ChannelEofEvent
    | ChannelOpenEvent
    | ChannelDataEvent
    | SessionSetEnvEvent
    | SessionExecEvent
    | SessionShellEvent
)
