from dataclasses import dataclass
from typing import Annotated, ClassVar, Literal

from ..encoding import Codable, Name, UnionAnnotation
from ..terminal_modes import TerminalModes
from .base import DecodableMessage, EncodableMessage
from .types import LanguageTag


# See: RFC 4254


## Channel request details

# Section 6.4

@dataclass(kw_only=True, slots=True)
class ChannelRequestDetailsEnv(Codable):
  key: ClassVar[str] = 'env'

  name: bytes
  value: bytes


# Section 6.2

@dataclass(kw_only=True, slots=True)
class ChannelRequestDetailsPtyReq(Codable):
  key: ClassVar[str] = 'pty-req'

  term_name: bytes
  term_width_chars: int
  term_height_chars: int
  term_width_pixels: int
  term_height_pixels: int
  term_modes: TerminalModes


# Section 6.5

@dataclass(slots=True)
class ChannelRequestDetailsShell(Codable):
  key: ClassVar[str] = 'shell'

@dataclass(slots=True)
class ChannelRequestDetailsExec(Codable):
  key: ClassVar[str] = 'exec'

  command: bytes

@dataclass(slots=True)
class ChannelRequestDetailsSubsystem(Codable):
  key: ClassVar[str] = 'subsystem'

  name: bytes


# Section 6.7

@dataclass(slots=True)
class ChannelRequestDetailsWindowChange(Codable):
  key: ClassVar[str] = 'window-change'

  term_width_chars: int
  term_height_chars: int
  term_width_pixels: int
  term_height_pixels: int


# Section 6.8

@dataclass(slots=True)
class ChannelRequestDetailsXonXoff(Codable):
  key: ClassVar[str] = 'xon-xoff'

  # want_reply: Literal[False]
  client_can_do: bool


# Section 6.9

@dataclass(slots=True)
class ChannelRequestDetailsSignal(Codable):
  key: ClassVar[str] = 'signal'

  # want_reply: Literal[False]
  signal_name: bytes


# Section 6.10

type SignalName = Literal['ABRT', 'ALRM', 'FPE', 'HUP', 'ILL', 'INT', 'KILL', 'PIPE', 'QUIT', 'SEGV', 'TERM', 'USR1', 'USR2']

@dataclass(slots=True)
class ChannelRequestDetailsExitStatus(Codable):
  key: ClassVar[str] = 'exit-status'

  # want_reply: Literal[False]
  exit_status: int

@dataclass(slots=True)
class ChannelRequestDetailsExitSignal(Codable):
  key: ClassVar[str] = 'exit-signal'

  # want_reply: Literal[False]
  signal_name: Name
  core_dumped: bool
  error_message: str
  language_tag: LanguageTag


## Channel request message

# Section 4

@dataclass(kw_only=True, slots=True)
class ChannelRequestMessage(Codable, DecodableMessage):
  id: ClassVar[int] = 98

  recipient_channel_id: int
  request_type: Name
  want_reply: bool

  details: Annotated[
      ChannelRequestDetailsEnv
    | ChannelRequestDetailsPtyReq
    | ChannelRequestDetailsShell
    | ChannelRequestDetailsExec
    | ChannelRequestDetailsSubsystem
    | ChannelRequestDetailsWindowChange
    | ChannelRequestDetailsXonXoff
    | ChannelRequestDetailsSignal
    | ChannelRequestDetailsExitStatus
    | ChannelRequestDetailsExitSignal
    | None
  , UnionAnnotation('request_type', 'key')]


## Channel request response messages

# Section 5.4

@dataclass(kw_only=True, slots=True)
class ChannelSuccessMessage(Codable, EncodableMessage):
  id: ClassVar[int] = 99

  recipient_channel_id: int


@dataclass(kw_only=True, slots=True)
class ChannelFailureMessage(Codable, EncodableMessage):
  id: ClassVar[int] = 100

  recipient_channel_id: int
