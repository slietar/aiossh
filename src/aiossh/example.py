import asyncio
import logging
import os
import shlex
import signal
from asyncio import TaskGroup
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, override

import aiodrive

from siossh.connection import Connection, ConnectionSettings
from siossh.events import SessionPTYOptions
from siossh.integrations.asyncio import (
  AsyncConnectionClient,
  AsyncSessionClient,
  AsyncStream,
  attach_async_client,
)

from .host_keys import get_host_keys
from .subprocess import PTYSubprocess, RegularSubprocess, Subprocess


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class SubprocessSessionClient(AsyncSessionClient):
  command: Optional[str]
  env: Mapping[str, str]
  pty: Optional[SessionPTYOptions]

  subprocess: Subprocess = field(init=False)
  stream: AsyncStream = field(init=False)

  @override
  async def resize(self, window_chars: tuple[int, int], window_pixels: tuple[int, int], /) -> None:
    assert self.subprocess is not None
    assert isinstance(self.subprocess, PTYSubprocess)

    self.subprocess.resize(os.terminal_size([window_chars[0], window_chars[1]]))

  async def _pipe_stdout(self):
    assert self.subprocess is not None
    assert self.stream is not None

    while True:
      chunk = await self.subprocess.reader.read(self.stream.window_size)

      if not chunk:
        break

      # print(f'Writing chunk to stdout: {chunk!r}')
      await self.stream.write(chunk)

  async def _pipe_stderr(self):
    assert self.subprocess is not None
    assert self.stream is not None

    if self.subprocess.reader_error is None:
      return

    while True:
      chunk = await self.subprocess.reader_error.read(self.stream.window_size)

      if not chunk:
        break

      await self.stream.write(chunk, error=True)

  async def _pipe_stdin(self):
    while True:
      chunk = await self.stream.read()
      await self.subprocess.write(chunk)

      if not chunk:
        break

  @override
  async def run(self, stream: AsyncStream):
    self.stream = stream

    if self.command is not None:
      command = self.command
    else:
      command = shlex.join([os.environ['SHELL'], '-l'])

    if self.pty is not None:
      subproc = PTYSubprocess.create(
        command,
        cwd=Path.home(),
        env=self.env,
        terminal_size=os.terminal_size([
          self.pty.window_chars[0],
          self.pty.window_chars[1],
        ]),
        terminal_modes=self.pty.terminal_modes,
      )
    else:
      subproc = RegularSubprocess.create(
        command,
        cwd=Path.home(),
        env=self.env,
      )

    async with subproc as self.subprocess:
      LOGGER.debug(f'Subprocess started with pid {self.subprocess.process.pid}')

      async with TaskGroup() as group:
        group.create_task(self._pipe_stdout())
        group.create_task(self._pipe_stderr())
        group.create_task(self._pipe_stdin())

    LOGGER.debug(f'Subprocess exited with code {self.subprocess.code}')

    assert self.subprocess.code is not None
    self.stream.exit(self.subprocess.code)


@dataclass(slots=True)
class ExampleClient(AsyncConnectionClient):
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
  async def start_exec_session(self, command, env, pty):
    return SubprocessSessionClient(command=command, env=env, pty=pty)

  @override
  async def start_shell_session(self, env, pty):
    return SubprocessSessionClient(command=None, env=env, pty=pty)


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

  client = ExampleClient()

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
