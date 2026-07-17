from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional, Protocol

from .messages.channel import ChannelOpenFailureReason, ChannelOpenMessage
from .terminal_modes import TerminalModes


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
class DisconnectEvent:
  reason: int
  description: str

  # Whether the other party sent the disconnect message
  other: bool

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
class ChannelCloseEvent:
  channel_id: int


@dataclass(slots=True)
class ChannelDataEvent:
  channel_id: int
  chunk: bytes

@dataclass(slots=True)
class ChannelEofEvent:
  channel_id: int


@dataclass(slots=True)
class SessionPTYOptions:
  terminal_modes: TerminalModes
  terminal_name: bytes
  window_chars: tuple[int, int]
  window_pixels: tuple[int, int]

@dataclass(slots=True)
class SessionExecEvent:
  channel_id: int
  command: str
  env: dict[str, str]
  pty: Optional[SessionPTYOptions]

  accept: Callable[[], Stream]
  reject: Callable[[], None]

@dataclass(slots=True)
class SessionShellEvent:
  channel_id: int
  env: dict[str, str]
  pty: Optional[SessionPTYOptions]

  accept: Callable[[], Stream]
  reject: Callable[[], None]


@dataclass(slots=True)
class Stream:
    exit: Callable[[int], None]
    write: Callable[[bytes], None]


type Event = (
    AuthWithPasswordRequestEvent
    | AuthWithPublicKeyRequestEvent
    | DisconnectEvent
    | ExchangedKeysEvent
    | ChannelCloseEvent
    | ChannelEofEvent
    | ChannelOpenEvent
    | ChannelDataEvent
    | SessionExecEvent
    | SessionShellEvent
)
