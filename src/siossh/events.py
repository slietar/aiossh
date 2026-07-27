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
  """
  An event emitted when the connection is disconnected with a message, whether
  it was initiated by the other party or locally.

  No event follows this event, and the connection is considered closed after
  this event is emitted.
  """

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
  """
  An event emitted when a channel is explicitly closed by the other party.
  """

  channel_id: int


@dataclass(slots=True)
class ChannelDataEvent:
  channel_id: int
  chunk: bytes

@dataclass(slots=True)
class ChannelEofEvent:
  channel_id: int

@dataclass(slots=True)
class ChannelWindowAdjustEvent:
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
class PTYSessionTerminalSizeChangeEvent:
  channel_id: int
  window_chars: tuple[int, int]
  window_pixels: tuple[int, int]


class StreamWriteProtocol(Protocol):
  def __call__(self, data: bytes, /, *, error: bool = ...) -> None:
    ...

@dataclass(slots=True)
class Stream:
  exit: Callable[[int], None]
  reset_window: Callable[[], None]
  write: StreamWriteProtocol
  _get_window_size: Callable[[], int]

  @property
  def window_size(self):
    return self._get_window_size()


type Event = (
  AuthWithPasswordRequestEvent
  | AuthWithPublicKeyRequestEvent
  | DisconnectEvent
  | ExchangedKeysEvent
  | ChannelCloseEvent
  | ChannelEofEvent
  | ChannelOpenEvent
  | ChannelDataEvent
  | ChannelWindowAdjustEvent
  | PTYSessionTerminalSizeChangeEvent
  | SessionExecEvent
  | SessionShellEvent
)
