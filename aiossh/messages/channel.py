from dataclasses import dataclass
from enum import IntEnum
from typing import Annotated, ClassVar

from ..encoding import AutoCodable, UnionAnnotation
from .base import AutoCodableMessage
from .channel_request import ChannelRequestMessage
from .types import LanguageTag


# See: RFC 4254


## Open message details

# Section 6.1

@dataclass(kw_only=True, slots=True)
class ChannelOpenDetailsSession(AutoCodable):
  key: ClassVar[str] = 'session'


# Section 7.2

@dataclass(kw_only=True, slots=True)
class ChannelOpenDetailsDirectTcpIp(AutoCodable):
  key: ClassVar[str] = 'direct-tcpip'

  recipient_address: str
  recipient_port: int
  originator_address: str
  originator_port: int


# Section 7.2

@dataclass(kw_only=True, slots=True)
class ChannelOpenDetailsForwardedTcpIP(AutoCodable):
  key: ClassVar[str] = 'forwarded-tcpip'

  recipient_address: str
  recipient_port: int
  originator_address: str
  originator_port: int


# Section 6.3.2

@dataclass(kw_only=True, slots=True)
class ChannelOpenDetailsX11(AutoCodable):
  key: ClassVar[str] = 'x11'

  originator_address: str
  originator_port: int


type ChannelOpenDetails = (
    ChannelOpenDetailsDirectTcpIp
  | ChannelOpenDetailsForwardedTcpIP
  | ChannelOpenDetailsSession
  | ChannelOpenDetailsX11
)


## Open message

# Section 5.1

@dataclass(kw_only=True, slots=True)
class ChannelOpenMessage(AutoCodableMessage):
  id: ClassVar[int] = 90

  type: str
  sender_channel_id: int
  window_size: int
  max_packet_size: int

  details: Annotated[ChannelOpenDetails, UnionAnnotation('type', 'key')]


@dataclass(slots=True)
class ChannelOpenConfirmationMessage(AutoCodableMessage):
  id: ClassVar[int] = 91

  recipient_channel_id: int
  sender_channel_id: int
  window_size: int
  max_packet_size: int

  # details: ChannelOpenDetails


class ChannelOpenFailureReason(IntEnum):
  AdministrativelyProhibited = 1
  ConnectFailed = 2
  UnknownChannelType = 3
  ResourceShortage = 4

@dataclass(kw_only=True, slots=True)
class ChannelOpenFailureMessage(AutoCodableMessage):
  id: ClassVar[int] = 92

  recipient_channel_id: int
  reason_code: int # Using int instead of ChannelOpenFailureReason as there can be custom codes
  description: str
  language_tag: LanguageTag


## Data messages

class DataTypeCode(IntEnum):
  Stderr = 1

@dataclass(kw_only=True, slots=True)
class ChannelDataMessage(AutoCodableMessage):
  id: ClassVar[int] = 94

  recipient_channel_id: int
  data: bytes

@dataclass(kw_only=True, slots=True)
class ChannelExtendedDataMessage(AutoCodableMessage):
  id: ClassVar[int] = 95

  recipient_channel_id: int
  data_type_code: int
  data: bytes


## EOF message

@dataclass(kw_only=True, slots=True)
class ChannelEofMessage(AutoCodableMessage):
  id: ClassVar[int] = 96

  recipient_channel_id: int


## Close channel message

# Section 5.3

@dataclass(kw_only=True, slots=True)
class ChannelCloseMessage(AutoCodableMessage):
  id: ClassVar[int] = 97

  recipient_channel_id: int


type OpenChannelMessage = (
    ChannelRequestMessage
  | ChannelOpenConfirmationMessage
  | ChannelOpenFailureMessage
  | ChannelDataMessage
  | ChannelExtendedDataMessage
  | ChannelEofMessage
  | ChannelCloseMessage
)
