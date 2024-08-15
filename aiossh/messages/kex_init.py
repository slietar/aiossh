import os
import struct
from dataclasses import dataclass
from typing import ClassVar

from .base import DecodableMessage, EncodableMessage
from ..structures.primitives import decode_name_list, encore_name_list
from ..util import ReadableBytesIO


# Client & server

@dataclass(frozen=True, kw_only=True, slots=True)
class KexInitMessage(DecodableMessage, EncodableMessage):
  id: ClassVar[int] = 20

  kex_algorithms: list[str]
  server_host_key_algorithms: list[str]
  encryption_algorithms_client_to_server: list[str]
  encryption_algorithms_server_to_client: list[str]
  mac_algorithms_client_to_server: list[str]
  mac_algorithms_server_to_client: list[str]
  compression_algorithms_client_to_server: list[str]
  compression_algorithms_server_to_client: list[str]
  languages_client_to_server: list[str]
  languages_server_to_client: list[str]
  first_kex_packet_follows: bool

  def encode(self):
    return os.urandom(16)\
      + encore_name_list(self.kex_algorithms)\
      + encore_name_list(self.server_host_key_algorithms)\
      + encore_name_list(self.encryption_algorithms_client_to_server)\
      + encore_name_list(self.encryption_algorithms_server_to_client)\
      + encore_name_list(self.mac_algorithms_client_to_server)\
      + encore_name_list(self.mac_algorithms_server_to_client)\
      + encore_name_list(self.compression_algorithms_client_to_server)\
      + encore_name_list(self.compression_algorithms_server_to_client)\
      + encore_name_list(self.languages_client_to_server)\
      + encore_name_list(self.languages_server_to_client)\
      + struct.pack('>?I', False, 0)


  @classmethod
  def decode(cls, reader: ReadableBytesIO):
    reader.read(16)

    return cls(
      kex_algorithms=decode_name_list(reader),
      server_host_key_algorithms=decode_name_list(reader),
      encryption_algorithms_client_to_server=decode_name_list(reader),
      encryption_algorithms_server_to_client=decode_name_list(reader),
      mac_algorithms_client_to_server=decode_name_list(reader),
      mac_algorithms_server_to_client=decode_name_list(reader),
      compression_algorithms_client_to_server=decode_name_list(reader),
      compression_algorithms_server_to_client=decode_name_list(reader),
      languages_client_to_server=decode_name_list(reader),
      languages_server_to_client=decode_name_list(reader),
      first_kex_packet_follows=struct.unpack('>?', reader.read(1))[0]
    )
