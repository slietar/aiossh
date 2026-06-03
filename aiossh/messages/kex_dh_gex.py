from dataclasses import dataclass
from typing import Annotated, ClassVar

from ..encoding import EncodingAnnotation
from .base import AutoCodableMessage


# Client-only

@dataclass(kw_only=True, slots=True)
class KexDhGexRequestMessage(AutoCodableMessage):
  id: ClassVar[int] = 34

  min: int
  n: int
  max: int


# Server-only

@dataclass(kw_only=True, slots=True)
class KexDhGexGroupMessage(AutoCodableMessage):
  id: ClassVar[int] = 31

  p: Annotated[int, EncodingAnnotation('mpint')]
  g: Annotated[int, EncodingAnnotation('mpint')]


# Client-only

@dataclass(kw_only=True, slots=True)
class KexDhGexInitMessage(AutoCodableMessage):
  id: ClassVar[int] = 32

  e: Annotated[int, EncodingAnnotation('mpint')]


# Server-only

@dataclass(kw_only=True, slots=True)
class KexDhGexReplyMessage(AutoCodableMessage):
  id: ClassVar[int] = 33

  host_key: bytes
  f: Annotated[int, EncodingAnnotation('mpint')]
  signature: bytes
