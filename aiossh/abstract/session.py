from asyncio import StreamReader
from codecs import StreamWriter
from collections.abc import AsyncIterable, Awaitable
from dataclasses import dataclass
from typing import Protocol

from ..messages.channel_request import SignalName
from ..messages.types import LanguageTag


# class SessionError(Exception):
#   pass


# class ForwardingHandle(Awaitable[None]):
#   pass


@dataclass(slots=True)
class SessionExitStatus:
  value: int

@dataclass(slots=True)
class SessionExitSignal:
  core_dumped: bool
  error_message: str
  language_tag: LanguageTag
  signal_name: SignalName

type SessionResult = SessionExitStatus | SessionExitSignal


# class SessionSetup(ABC):
#   @abstractmethod
#   def set_env(self, key: str, value: str) -> None:
#     ...

#   @abstractmethod
#   def set_window(self, width: int, height: int) -> None:
#     ...

#   # @abstractmethod
#   # def receive_signal(self, name: SignalName) -> None:
#   #   ...


class Stream[T](AsyncIterable[T], Protocol):
  ...


@dataclass(slots=True)
class SessionSettings:
  env: dict[str, str]

class Session(Protocol):
  settings: SessionSettings
  window: tuple[int, int]

  stdin: StreamReader
  stdout: StreamWriter
  stderr: StreamWriter

  signal_stream: Stream[SignalName]
  window_change: Awaitable[None]

  def send_exit_status(self, status: int) -> None:
    ...

  def send_signal_exited(self, signal: SignalName, error_message: str, language_tag: str, *, core_dumped: bool) -> None:
    ...
