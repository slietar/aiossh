from asyncio import StreamReader, StreamWriter
from dataclasses import dataclass, field

from .abstract.client import Client
from .connection import Connection
from .host_key import HostKey
from .primes.group import Group
from .primes.well_known import groups as well_known_dh_groups


@dataclass(kw_only=True, slots=True)
class Server:
  host_keys: list[HostKey]

  dh_groups: list[Group] = field(default_factory=(lambda: well_known_dh_groups))
  software_version: str = 'aiossh_0.0.0'

  async def handle(self, client: Client, reader: StreamReader, writer: StreamWriter):
    conn = Connection(self, client, reader, writer)
    await conn.handle()
