import asyncio
import logging
import os
import pickle
import signal
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import aiodrive

from .connection_sansio import SansIOConnection, SansIOConnectionSettings
from .error import ConnectionTerminatedError
from .events import (
  AuthWithPasswordRequestEvent,
  AuthWithPublicKeyRequestEvent,
  ChannelDataEvent,
  ChannelEofEvent,
  ChannelOpenEvent,
  DataEvent,
  SessionExecEvent,
  SessionShellEvent,
  Stream,
)
from .pty import PTYSession, iter_reader
from .public.base import PrivateKey
from .public.rsa import RSAPrivateKey


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
  pty_session: Optional[PTYSession] = field(default=None, init=False)
  stream: Optional[Stream] = field(default=None, init=False)
  trigger: asyncio.Event

  def recv_stdin(self, chunk: bytes):
    assert self.pty_session is not None
    self.pty_session.write(chunk)

  async def start(self, event: SessionShellEvent):
    async with PTYSession.create(
      os.environ['SHELL'],
      cwd=Path.home(),
      env={
        'TERM': 'xterm-256color',
      },
      terminal_size=os.terminal_size([80, 24]),
      # terminal_size=os.terminal_size(session.settings.pty.window_chars),
    ) as self.pty_session:
      print(f'PTY session started with pid {self.pty_session.process.pid}')
      self.stream = event.accept()

      async def pipe_pty_to_stdout():
        assert self.pty_session is not None
        assert self.stream is not None

        async for chunk in iter_reader(self.pty_session.reader):
          print(repr(chunk))
          self.stream.write(chunk)
          self.trigger.set()

      async with asyncio.TaskGroup() as group:
        group.create_task(pipe_pty_to_stdout())
        # group.create_task(watch_terminal_size(session))

    print(f'PTY session exited with code {self.pty_session.code}')

    assert self.pty_session.code is not None
    self.stream.exit(self.pty_session.code)
    self.trigger.set()



async def main():
  LOGGER.debug(f'Process id: {os.getpid()}')

  async def tcp_handler(tcp_connection: aiodrive.Connection):
    LOGGER.debug(f'Incoming connection from {tcp_connection.client_name} to {tcp_connection.server_name}')

    conn = SansIOConnection(
      debug=True,
      settings=SansIOConnectionSettings(
        host_keys=get_host_keys(),
        software_version='aiossh_0.0.0',
        supported_auth_methods=['publickey'],
      ),
    )

    shell: Optional[Shell] = None
    trigger = asyncio.Event()

    async with asyncio.TaskGroup() as group:
      while True:
        # LOGGER.debug('Enumerating events...')

        try:
          trigger.clear()

          for event in conn.events():
            match event:
              case DataEvent(chunk):
                tcp_connection.writer.write(chunk)
                await tcp_connection.writer.drain()
              case AuthWithPasswordRequestEvent():
                event.respond(True)
              case AuthWithPublicKeyRequestEvent():
                event.respond(True)
              case ChannelOpenEvent():
                channel_id = event.accept()
                print(f'Accepted open channel request with channel id {channel_id}')
              case SessionExecEvent(command=command):
                print(f'Session exec request with command "{command}"')
                stream = event.accept()
                # stream.write(b'Hello, world!\n')
                # stream.exit(7)
              case ChannelDataEvent(channel_id=channel_id, chunk=chunk):
                assert shell is not None
                assert shell.stream is not None

                shell.recv_stdin(chunk)
              case ChannelEofEvent(channel_id=channel_id):
                assert shell is not None
                assert shell.stream is not None

                # shell.stream.exit(7)
              case SessionShellEvent():
                shell = Shell(trigger=trigger)
                group.create_task(shell.start(event))
              case _:
                print('Event:', event)

          try:
            index, chunk = await aiodrive.race(
              tcp_connection.reader.read(65_536),
              trigger.wait(),
            )
          except BaseException as e:
            print(repr(e))
            conn.close()

            for event in conn.events():
              match event:
                case DataEvent(chunk):
                  tcp_connection.writer.write(chunk)
                  await tcp_connection.writer.drain()

            raise

          if index == 0:
            if not chunk:
              break

            assert isinstance(chunk, bytes)
            conn.feed(chunk)
        except ConnectionTerminatedError:
          LOGGER.debug('Connection terminated error')
          break


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
