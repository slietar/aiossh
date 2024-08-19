import asyncio
from asyncio import StreamReader, StreamWriter
from dataclasses import dataclass, field
import logging
from typing import Sequence

from aiodrive import Pool

from .connection import Connection
from .host_key import HostKey
from .prime import Prime, load_paths


logging.basicConfig(level=logging.DEBUG)


@dataclass(kw_only=True, slots=True)
class Server:
  host_keys: list[HostKey]

  primes: list[Prime] = field(default_factory=(lambda: list(load_paths())))
  software_version: str = 'aiossh_0.0.0'

  async def serve(self, host: Sequence[str] | str, port: int):
    async with Pool.open() as pool:
      def handle_connection_sync(reader: StreamReader, writer: StreamWriter):
        # print(writer.transport.get_protocol())
        # print(writer.transport.get_extra_info('peername'))
        # print(writer.transport.get_write_buffer_limits())
        # print(writer.transport.get_write_buffer_size())

        conn = Connection(self, reader, writer)
        pool.spawn(conn.handle(), depth=1)


      server = await asyncio.start_server(handle_connection_sync, host, port)

      pool.spawn(server.serve_forever())
