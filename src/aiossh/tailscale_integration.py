import asyncio
from dataclasses import dataclass, field
from typing import cast

import aiodrive
import tailscale


@dataclass(slots=True)
class _TailscaleStreamReader:
  """Adapts `tailscale.TcpStream.recv()` to the `asyncio.StreamReader.read()` shape."""

  stream: tailscale.TcpStream
  buffer: bytes = field(default=b'', init=False)

  async def read(self, n: int = -1) -> bytes:
    if not self.buffer:
      self.buffer = await self.stream.recv()

    if n < 0:
      chunk, self.buffer = self.buffer, b''
    else:
      chunk, self.buffer = self.buffer[:n], self.buffer[n:]

    return chunk


@dataclass(slots=True)
class _TailscaleStreamWriter:
  """Adapts `tailscale.TcpStream.send()` to the `asyncio.StreamWriter` write/drain shape."""

  stream: tailscale.TcpStream
  pending: bytes = field(default=b'', init=False)

  def write(self, data: bytes) -> None:
    self.pending += data

  async def drain(self) -> None:
    while self.pending:
      sent = await self.stream.send(self.pending)
      self.pending = self.pending[sent:]

  def close(self) -> None:
    pass

  async def wait_closed(self) -> None:
    pass


def tailscale_connection(stream: tailscale.TcpStream) -> aiodrive.Connection:
  """Wraps an established `tailscale.TcpStream` as an `aiodrive.Connection`."""

  client_host, client_port = stream.remote_addr()
  server_host, server_port = stream.local_addr()

  return aiodrive.Connection(
    client_name=aiodrive.SocketName(client_host, client_port),
    server_name=aiodrive.SocketName(server_host, server_port),
    reader=cast(asyncio.StreamReader, _TailscaleStreamReader(stream)),
    writer=cast(asyncio.StreamWriter, _TailscaleStreamWriter(stream)),
  )


__all__ = [
  'tailscale_connection',
]
