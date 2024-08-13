import asyncio
from asyncio import StreamReader, StreamWriter
from dataclasses import dataclass, field
from typing import Sequence

from .connection import Connection
from .host_key import HostKey
from .prime import Prime, load_paths


@dataclass(kw_only=True, slots=True)
class Server:
  host_keys: list[HostKey]

  primes: list[Prime] = field(default_factory=(lambda: list(load_paths())))
  software_version: str = 'aiossh_0.1.0'

  async def serve(self, host: Sequence[str] | str, port: int):
    async def handle_connection_sync(reader: StreamReader, writer: StreamWriter):
      conn = Connection(self, reader, writer)
      await conn.handle()

    server = await asyncio.start_server(handle_connection_sync, host, port)

    await server.serve_forever()
