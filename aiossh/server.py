from asyncio import StreamReader, StreamWriter
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address
from typing import Protocol

from .client import BaseClient
from .connection import Connection
from .host_key import HostKey
from .primes.group import Group
from .primes.well_known import groups as well_known_dh_groups


class CreateClientType(Protocol):
  def __call__(self, addr: IPv4Address | IPv6Address, port: int) -> BaseClient:
    ...

@dataclass(kw_only=True, slots=True)
class Server:
  host_keys: list[HostKey]

  dh_groups: list[Group] = field(default_factory=(lambda: well_known_dh_groups))
  software_version: str = 'aiossh_0.0.0'

  async def handle(self, client: BaseClient, reader: StreamReader, writer: StreamWriter):
    conn = Connection(self, client, reader, writer)
    await conn.handle()
