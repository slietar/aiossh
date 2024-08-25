import os
from dataclasses import dataclass, field
from typing import Annotated, ClassVar, final

from ..encoding import Codable, FixedSizeBytesAnnotation, NameList
from .base import Message


# Client & server

@final
@dataclass(kw_only=True, slots=True)
class KexInitMessage(Codable, Message):
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
