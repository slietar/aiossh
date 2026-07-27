import asyncio
import logging
import signal
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Optional, override

import aiodrive

from siossh.connection import Connection, ConnectionSettings
from siossh.events import SessionPTYOptions
from siossh.integrations.asyncio import (
  AsyncConnectionClient,
  attach_async_client,
)

from .host_keys import get_host_keys


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class TestClient(AsyncConnectionClient):
  name: Optional[str] = None

  @override
  async def auth_with_password(self, name: str, password: str) -> bool:
    LOGGER.debug('Called auth_with_password()')
    return True

  @override
  async def auth_with_public_key(self, name: str, public_key: bytes, authenticating: bool) -> bool:
    LOGGER.debug(f'Called auth_with_public_key(authenticating={authenticating})')

    if authenticating:
      self.name = name
      LOGGER.info(f'Authenticated user {name!r}')

    return True

  @override
  async def close(self) -> None:
    LOGGER.debug('Called close()')

  @override
  async def disconnect(self, reason: int, description: str) -> None:
    LOGGER.debug('Called disconnect()')

  @override
  async def start_exec_session(self, command: str, env: Mapping[str, str], pty: SessionPTYOptions | None):
    return None

  @override
  async def start_shell_session(self, env: Mapping[str, str], pty: SessionPTYOptions | None):
    return None


async def tcp_handler(tcp_connection: aiodrive.Connection):
  LOGGER.debug(f'Incoming connection from {tcp_connection.client_name} to {tcp_connection.server_name}')

  conn = Connection(
    debug=True,
    settings=ConnectionSettings(
      host_keys=get_host_keys(),
      software_version='aiossh_0.0.0',
      supported_auth_methods=['publickey'],
    ),
  )

  async def read() -> bytes:
    return await tcp_connection.reader.read(65_536)

  async def write(chunk: bytes):
    tcp_connection.writer.write(chunk)
    await tcp_connection.writer.drain()

  client = TestClient()

  await attach_async_client(
    conn,
    client,
    read=read,
    write=write,
  )


async def main():
  try:
    with aiodrive.handle_signal([signal.SIGINT, signal.SIGTERM]):
      async with aiodrive.TCPServer.listen(
        tcp_handler,
        host=['127.0.0.1', '::1'],
        port=1302,
      ) as tcp_server:
        for binding in tcp_server.bindings:
          LOGGER.info(f'Listening on {binding}')

        await aiodrive.wait_forever()
  except aiodrive.SignalHandledException as e:
    print('\r', end='')
    LOGGER.info(f'Received {signal.Signals(e.signal).name}')


if __name__ == '__main__':
  logging.basicConfig(
    format='[%(levelname)s] %(name)s    %(message)s',
    level=logging.DEBUG,
  )

  asyncio.run(main())
