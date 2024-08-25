import asyncio
import contextlib
from asyncio import Queue, QueueEmpty, QueueFull, StreamReader, StreamWriter
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address
from typing import Sequence


@dataclass(frozen=True, slots=True)
class SockName:
  address: IPv4Address | IPv6Address
  port: int

  def __str__(self):
    return f'{self.address}:{self.port}'

  @classmethod
  def parse(cls, name: tuple, /):
    match name:
      case host, port:
        addr = IPv4Address(host)
      case host, port, flowinfo, scopeid:
        addr = IPv6Address(host)
      case _:
        raise ValueError(f'Invalid peername: {name}')

    return cls(addr, port)


@contextlib.asynccontextmanager
async def serve_tcp(host: Sequence[str] | str, port: int):
  queue = Queue[tuple[StreamReader, StreamWriter]]()

  def handle_connection_sync(reader: StreamReader, writer: StreamWriter):
    try:
      queue.put_nowait((reader, writer))
    except QueueFull:
      writer.close()

  server = await asyncio.start_server(handle_connection_sync, host, port)
  bindings = frozenset({ SockName.parse(sock.getsockname()) for sock in server.sockets })

  try:
    yield TcpServer(bindings, queue)
  finally:
    try:
      while True:
        reader, writer = queue.get_nowait()
        writer.close()
    except QueueEmpty:
      pass

    server.close()
    await server.wait_closed()


@dataclass(slots=True)
class IncomingInfo:
  client_name: SockName
  server_name: SockName

  # _entered: bool = field(default=False, init=False, repr=False)
  reader: StreamReader = field(repr=False)
  writer: StreamWriter = field(repr=False)

  # def __enter__(self):
  #   if self._entered:
  #     raise RuntimeError('Already used incoming connection')

  #   self._entered = True
  #   return self._reader, self._writer

  # def __exit__(self, exc_type, exc_value, traceback):
  #   pass

  #   self._writer.close()


@dataclass(slots=True)
class TcpServer:
  names: frozenset[SockName]
  queue: Queue[tuple[StreamReader, StreamWriter]]

  async def __aiter__(self):
    while True:
      reader, writer = await self.queue.get()
      socket = writer.transport.get_extra_info('socket')

      client_name = SockName.parse(socket.getpeername())
      server_name = SockName.parse(socket.getsockname())

      info = IncomingInfo(
        client_name,
        server_name,

        reader,
        writer
      )

      yield info

      # if not info._entered:
      #   writer.close()
