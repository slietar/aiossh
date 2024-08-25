from asyncio import StreamReader, StreamWriter
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address
from typing import Protocol

from .client import BaseClient
from .connection import Connection
from .host_key import HostKey
from .prime import Prime, load_paths


class CreateClientType(Protocol):
  def __call__(self, addr: IPv4Address | IPv6Address, port: int) -> BaseClient:
    ...

@dataclass(kw_only=True, slots=True)
class Server:
  host_keys: list[HostKey]

  primes: list[Prime] = field(default_factory=(lambda: list(load_paths())))
  software_version: str = 'aiossh_0.0.0'

  async def handle(self, client: BaseClient, reader: StreamReader, writer: StreamWriter):
    conn = Connection(self, client, reader, writer)
    await conn.handle()
