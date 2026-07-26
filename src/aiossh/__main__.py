import asyncio
import logging
import os
import pickle
import shlex
import signal
from asyncio import Event
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import aiodrive

from siossh.connection import Connection, SansIOConnectionSettings
from siossh.error import ConnectionTerminatedError, UnreachableError
from siossh.events import (
  AuthWithPasswordRequestEvent,
  AuthWithPublicKeyRequestEvent,
  ChannelCloseEvent,
  ChannelDataEvent,
  ChannelEofEvent,
  ChannelOpenEvent,
  DisconnectEvent,
  PTYSessionTerminalSizeChangeEvent,
  SessionExecEvent,
  SessionShellEvent,
  Stream,
)
from siossh.public.base import PrivateKey
from siossh.public.rsa import RSAPrivateKey

from .subprocess import PTYSubprocess, RegularSubprocess, Subprocess


LOGGER = logging.getLogger(__name__)


def get_host_keys():
  host_keys_path = Path('tmp/keys.pkl')

  if host_keys_path.exists():
    with host_keys_path.open('rb') as file:
      host_keys: list[PrivateKey] = pickle.load(file)
  else:
    host_keys: list[PrivateKey] = [
      RSAPrivateKey.generate(),
    ]

    host_keys_path.parent.mkdir(exist_ok=True, parents=True)

    with host_keys_path.open('wb') as file:
      pickle.dump(host_keys, file)

  return host_keys


@dataclass(slots=True)
class Shell:
  queue: asyncio.Queue[bytes] = field(default_factory=asyncio.Queue, init=False)
  subprocess: Optional[Subprocess] = field(default=None, init=False)
  stream: Optional[Stream] = field(default=None, init=False)

  event_trigger: asyncio.Event
  send_trigger: asyncio.Event

  def recv_stdin(self, chunk: bytes):
    self.queue.put_nowait(chunk)

  def recv_stdin_eof(self):
    self.queue.shutdown()

  def set_terminal_size(self, rows: int, cols: int):
    assert self.subprocess is not None
    assert isinstance(self.subprocess, PTYSubprocess)

    self.subprocess.resize(os.terminal_size([rows, cols]))

  async def _pipe_stdout(self):
    assert self.subprocess is not None
    assert self.stream is not None

    while True:
      chunk = await self.subprocess.reader.read(self.stream.window_size)

      if not chunk:
        break

      self.stream.write(chunk)
      self.send_trigger.set()

  async def _pipe_stderr(self):
    assert self.subprocess is not None
    assert self.stream is not None

    if self.subprocess.reader_error is None:
      return

    while True:
      chunk = await self.subprocess.reader_error.read(self.stream.window_size)

      if not chunk:
        break

      self.stream.write(chunk, error=True)
      self.send_trigger.set()

  async def _pipe_stdin(self):
    assert self.subprocess is not None
    assert self.stream is not None

    while True:
      try:
        chunk = await self.queue.get()
      except asyncio.QueueShutDown:
        await self.subprocess.write(b'')
        break

      await self.subprocess.write(chunk)

      self.stream.reset_window()
      self.send_trigger.set()

  async def start(self, event: SessionExecEvent | SessionShellEvent):
    match event:
      case SessionExecEvent():
        command = event.command
      case SessionShellEvent():
        command = shlex.join([os.environ['SHELL'], '-l'])
      case _:
        raise UnreachableError

    if event.pty is not None:
      subproc = PTYSubprocess.create(
        command,
        cwd=Path.home(),
        env=event.env,
        terminal_size=os.terminal_size([
          event.pty.window_chars[0],
          event.pty.window_chars[1],
        ]),
        terminal_modes=event.pty.terminal_modes,
      )
    else:
      subproc = RegularSubprocess.create(
        command,
        cwd=Path.home(),
        env=event.env,
      )

    async with subproc as self.subprocess:
      LOGGER.debug(f'Subprocess started with pid {self.subprocess.process.pid}')
      self.stream = event.accept()

      self.event_trigger.set()
      self.send_trigger.set()

      async with asyncio.TaskGroup() as group:
        group.create_task(self._pipe_stdout())
        group.create_task(self._pipe_stderr())
        group.create_task(self._pipe_stdin())


    LOGGER.debug(f'Subprocess exited with code {self.subprocess.code}')

    assert self.subprocess.code is not None
    self.stream.exit(self.subprocess.code)
    self.send_trigger.set()



async def main():
  LOGGER.debug(f'Process id: {os.getpid()}')

  async def tcp_handler(tcp_connection: aiodrive.Connection):
    LOGGER.debug(f'Incoming connection from {tcp_connection.client_name} to {tcp_connection.server_name}')

    conn = Connection(
      debug=True,
      settings=SansIOConnectionSettings(
        host_keys=get_host_keys(),
        software_version='aiossh_0.0.0',
        supported_auth_methods=['publickey'],
      ),
    )

    shells = dict[int, Shell]()

    event_trigger = Event()
    send_trigger = Event()

    async def send_loop():
      while True:
        while (chunk := conn.get_send_buffer(65_536)):
          tcp_connection.writer.write(chunk)
          await tcp_connection.writer.drain()

        await send_trigger.wait()
        send_trigger.clear()

    try:
      async with aiodrive.volatile_task_group() as group:
        group.create_task(send_loop())

        while True:
          # LOGGER.debug('Enumerating events...')

          for event in conn.events():
            match event:
              case DisconnectEvent(reason=reason, description=description):
                LOGGER.info(f'Disconnect event with reason {reason} and description "{description}"')
                return

              case AuthWithPasswordRequestEvent():
                event.respond(True)
              case AuthWithPublicKeyRequestEvent():
                event.respond(True)

              case ChannelCloseEvent():
                LOGGER.info(f'Channel closed with channel id {event.channel_id}')
                del shells[event.channel_id]

              case ChannelOpenEvent():
                channel_id = event.accept()
                LOGGER.info(f'Accepted channel request with channel id {channel_id}')

              case SessionExecEvent(command=command):
                LOGGER.info(f'Session exec request with command "{command}"')

                shell = Shell(event_trigger=event_trigger, send_trigger=send_trigger)
                shells[event.channel_id] = shell

                group.create_task(shell.start(event))
              case SessionShellEvent():
                shell = Shell(event_trigger=event_trigger, send_trigger=send_trigger)
                shells[event.channel_id] = shell

                group.create_task(shell.start(event))

              case ChannelDataEvent(channel_id=channel_id, chunk=chunk):
                shell = shells[channel_id]
                assert shell.stream is not None

                shell.recv_stdin(chunk)
              case ChannelEofEvent(channel_id=channel_id):
                shell = shells[channel_id]
                assert shell.stream is not None

                shell.recv_stdin_eof()

              case PTYSessionTerminalSizeChangeEvent():
                shell = shells[event.channel_id]
                assert shell.stream is not None

                shell.set_terminal_size(event.window_chars[0], event.window_chars[1])

              case _:
                LOGGER.info(f'Event: {event}')

          try:
            index, chunk = await aiodrive.race(
              tcp_connection.reader.read(65_536),
              event_trigger.wait(),
            )
          except asyncio.CancelledError:
            conn.close()
            raise
          except ConnectionError:
            LOGGER.info('Connection error')
            return

          event_trigger.clear()

          if index == 0:
            assert isinstance(chunk, bytes)

            conn.feed(chunk)
            send_trigger.set()

    except* ConnectionTerminatedError:
      LOGGER.debug('Connection terminated error')

    LOGGER.debug(f'Closing connection from {tcp_connection.client_name}')


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
