import argparse
import asyncio
import functools
import logging
import os
import shlex
import signal
from asyncio import TaskGroup
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, cast, override

import aiodrive
import tailscale
from textual.driver import Driver

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
from .textual_driver import SSHDriver
from .trains.textual_demo import DemoApp


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
class TextualSessionClient(AsyncSessionClient):
  """Runs `DemoApp` in-process, wiring its input/output to the SSH channel's `AsyncStream`."""

  user_name: str
  client_name: str
  pty: SessionPTYOptions

  driver: Optional[SSHDriver] = field(default=None, init=False)
  driver_ready: asyncio.Event = field(default_factory=asyncio.Event, init=False)
  write_queue: asyncio.Queue[bytes] = field(default_factory=asyncio.Queue, init=False)

  def write(self, data: bytes):
    self.write_queue.put_nowait(data)

  async def _pipe_stdin(self, stream: AsyncStream):
    await self.driver_ready.wait()
    assert self.driver is not None

    while True:
      chunk = await stream.read()

      if not chunk:
        break

      self.driver.feed(chunk)

  async def _pipe_stdout(self, stream: AsyncStream):
    while True:
      chunk = await self.write_queue.get()
      await stream.write(chunk)

  @override
  async def resize(self, window_chars: tuple[int, int], window_pixels: tuple[int, int], /) -> None:
    if self.driver is not None:
      self.driver.resize(window_chars[0], window_chars[1])

  @override
  async def run(self, stream: AsyncStream) -> None:
    app = DemoApp(user_name=self.user_name, client_name=self.client_name)
    app.driver_class = cast(type[Driver], functools.partial(SSHDriver, session=self))

    async with aiodrive.volatile_task_group() as group:
      group.create_task(self._pipe_stdin(stream))
      group.create_task(self._pipe_stdout(stream))

      await app.run_async(mouse=True, size=self.pty.window_chars)

    LOGGER.debug('Textual app exited')

    stream.exit(0)


@dataclass(slots=True)
class ExampleClient(AsyncConnectionClient):
  client_name: str
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
    if pty is not None:
      return TextualSessionClient(
        user_name=self.name or 'anonymous',
        client_name=self.client_name,
        pty=pty,
      )

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
    await tcp_connection.writer.write(chunk)

  client = ExampleClient(client_name=str(tcp_connection.client_name))

  await attach_async_client(
    conn,
    client,
    read=read,
    write=write,
  )


def parse_args():
  parser = argparse.ArgumentParser()
  parser.add_argument(
    '--tailscale-key-file',
    type=Path,
    default=None,
    help='Path to the Tailscale key file. If set, listen on a Tailscale device instead of a plain TCP socket.',
  )

  return parser.parse_args()


async def main():
  args = parse_args()

  try:
    with aiodrive.handle_signal([signal.SIGINT, signal.SIGTERM]):
      if args.tailscale_key_file is not None:
        os.environ['TS_RS_EXPERIMENT'] = 'this_is_unstable_software'

        device = await tailscale.connect(
          str(args.tailscale_key_file),
          auth_key=os.environ['TS_AUTH_KEY'],
          control_server_url=os.environ['TS_CONTROL_SERVER_URL'],
        )

        addr = await device.ipv4_addr()
        print(f'Tailscale device connected with IPv4 address: {addr}')

        context = aiodrive.TCPServer.listen_tailscale(
          tcp_handler,
          str(addr),
          device=device,
          port=22,
        )
      else:
        context = aiodrive.TCPServer.listen(
          tcp_handler,
          '0.0.0.0',
          port=1302,
        )

      async with context as tcp_server:
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
