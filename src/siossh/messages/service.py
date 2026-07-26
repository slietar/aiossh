from dataclasses import dataclass
from typing import ClassVar

from ..encoding import Name
from .base import AutoCodableMessage


# See: RFC 4253 Section 10

@dataclass(kw_only=True, slots=True)
class ServiceRequestMessage(AutoCodableMessage):
  id: ClassVar[int] = 5

  service_name: Name


@dataclass(kw_only=True, slots=True)
class ServiceAcceptMessage(AutoCodableMessage):
  id: ClassVar[int] = 6

  service_name: Name
