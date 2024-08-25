from dataclasses import dataclass
from typing import ClassVar

from ..encoding import Codable, Name
from .base import Message


# See: RFC 4253 Section 10

@dataclass(kw_only=True, slots=True)
class ServiceRequestMessage(Codable, Message):
  id: ClassVar[int] = 5

  service_name: Name


@dataclass(kw_only=True, slots=True)
class ServiceAcceptMessage(Codable, Message):
  id: ClassVar[int] = 6

  service_name: Name
