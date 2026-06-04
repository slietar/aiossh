import os
from dataclasses import dataclass, field
from typing import Annotated, ClassVar, final

from ..encoding import FixedSizeBytesAnnotation, Mpint, NameList
from .base import AutoCodableMessage


## General

# Client & server

@final
@dataclass(kw_only=True, slots=True)
class KexInitMessage(AutoCodableMessage):
  id: ClassVar[int] = 20

  _random: Annotated[bytes, FixedSizeBytesAnnotation(16)] = field(default_factory=(lambda: os.urandom(16)), init=False, repr=False)
  kex_algorithms: NameList
  server_host_key_algorithms: NameList
  encryption_algorithms_client_to_server: NameList
  encryption_algorithms_server_to_client: NameList
  mac_algorithms_client_to_server: NameList
  mac_algorithms_server_to_client: NameList
  compression_algorithms_client_to_server: NameList
  compression_algorithms_server_to_client: NameList
  languages_client_to_server: NameList
  languages_server_to_client: NameList
  first_kex_packet_follows: bool
  _reserved: int = field(default=0, init=False, repr=False)


## Diffie-Hellman Group Exchange (DH-GEX)
# See: RFC 4419

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

  p: Mpint
  g: Mpint


# Client-only

@dataclass(kw_only=True, slots=True)
class KexDhGexInitMessage(AutoCodableMessage):
  id: ClassVar[int] = 32

  e: Mpint


# Server-only

@dataclass(kw_only=True, slots=True)
class KexDhGexReplyMessage(AutoCodableMessage):
  id: ClassVar[int] = 33

  host_key: bytes
  f: Mpint
  signature: bytes


## ECDH, ED25519
# See: RFC 5656 Section 4

@dataclass(kw_only=True, slots=True)
class KexEcdhInitMessage(AutoCodableMessage):
    id: ClassVar[int] = 30

    q_h: bytes

@dataclass(kw_only=True, slots=True)
class KexEcdhReplyMessage(AutoCodableMessage):
    id: ClassVar[int] = 31

    k_s: bytes
    q_s: bytes
    signature: bytes
