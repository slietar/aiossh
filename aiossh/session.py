from dataclasses import dataclass, field
from typing import Optional

from .stream import AsyncReadableStreamImpl, AsyncWritableStreamImpl
from .terminal_modes import TerminalModes


@dataclass(slots=True)
class SessionPTY:
  terminal_modes: TerminalModes
  terminal_name: bytes
  window_chars: tuple[int, int]
  window_pixels: tuple[int, int]

@dataclass(slots=True)
class SessionSettings:
  env: dict[str, str] = field(default_factory=dict)
  pty: Optional[SessionPTY] = None


@dataclass(kw_only=True, slots=True)
class SessionActivity:
  stdin: AsyncReadableStreamImpl = field(default_factory=AsyncReadableStreamImpl, init=False)
  stdout: AsyncWritableStreamImpl
  stderr: AsyncWritableStreamImpl

  # signal_stream: Stream[SignalName]
  # window_change: Awaitable[None]

  # def send_exit_status(self, status: int) -> None:
  #   ...

  # def send_signal_exited(self, signal: SignalName, error_message: str, language_tag: LanguageTag, *, core_dumped: bool) -> None:
  #   ...


@dataclass(slots=True)
class Session:
  activity: Optional[SessionActivity] = field(default=None, init=False)
  client_channel_id: int
  settings: SessionSettings = field(default_factory=SessionSettings, init=False)
