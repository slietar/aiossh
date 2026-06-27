import array
import asyncio
import contextlib
import fcntl
import logging
import os
import pty
import signal
import sys
import termios
import tty
from asyncio import StreamReader, TaskGroup
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Optional

import aiodrive

from .stream import AsyncReadableStreamProtocol


logger = logging.getLogger(__name__)


@dataclass(slots=True)
class PTYSession:
  _master_fd: int = field(repr=False)
  process: aiodrive.Process
  reader: StreamReader

  code: Optional[int] = None

  def resize(self, size: os.terminal_size, /):
    buf = array.array('H', [size.lines, size.columns, 0, 0])
    fcntl.ioctl(self._master_fd, termios.TIOCSWINSZ, buf)

  def write(self, data: bytes, /):
    os.write(self._master_fd, data)

  @classmethod
  @contextlib.asynccontextmanager
  async def create(cls, command: str, *, cwd: Path, env: Mapping[str, str], terminal_size: os.terminal_size):
    master_fd, slave_fd = pty.openpty()

    process = await aiodrive.start_process(
      command,
      cwd=cwd,
      env=env,
      stderr=slave_fd,
      stdin=slave_fd,
      stdout=slave_fd,
    )

    async def wait():
      await process.wait(first_signal=signal.SIGTERM)
      raise aiodrive.ProcessTerminatedException(0)

    session = None

    try:
      async with aiodrive.contextualize(wait()):
        try:
          os.close(slave_fd)

          reader = await aiodrive.get_reader(
            os.fdopen(master_fd, mode='rb'),
          )

          session = cls(master_fd, process, reader)
          session.resize(terminal_size)
        except Exception as e:
          logger.error(f'Failed to setup process + {e}')
        else:
          yield session
    except aiodrive.ProcessTerminatedException as e: # TODO: Use except*
      logger.info(f'Process terminated with code {e.code}')

      if session is not None:
        session.code = e.code & 0xff
    else:
      logger.info('Process exited normally')

      if session is not None:
        session.code = 0


@contextlib.contextmanager
def unbuffered_tty(file: IO[bytes], /):
  fd = file.fileno()
  attr = termios.tcgetattr(fd)
  tty.setcbreak(fd, termios.TCSANOW)

  try:
    yield
  finally:
    termios.tcsetattr(fd, termios.TCSANOW, attr)

async def iter_reader(reader: AsyncReadableStreamProtocol, /, *, chunk_size: int = 65_536):
  while True:
    chunk = await reader.read(chunk_size)

    if not chunk:
      break

    yield chunk


async def main():
  with unbuffered_tty(sys.stdin.buffer):
    stdin = await aiodrive.get_reader(sys.stdin.buffer)
    stdout = await aiodrive.get_writer(sys.stdout.buffer)

    async def pipe_stdin_to_pty(session: PTYSession):
      async for chunk in iter_reader(stdin):
        session.write(chunk)

    async def watch_terminal_size(session: PTYSession):
      while True:
        await aiodrive.wait_for_signal(signal.SIGWINCH)
        session.resize(os.get_terminal_size())

    session = None

    try:
      async with PTYSession.create(
        Path(os.environ['SHELL']).as_posix(),
        cwd=Path.home(),
        env=os.environ,
        terminal_size=os.get_terminal_size(),
      ) as session:
        print(f'Internal PID: {session.process.pid}')
        print('----')

        async with TaskGroup() as group:
          group.create_task(aiodrive.pipe(session.reader, stdout))
          group.create_task(pipe_stdin_to_pty(session))
          group.create_task(watch_terminal_size(session))

    finally:
      if session is not None:
        print('----')
        # print(f'Process exited with code {session.process.returncode}')


# import logging
# logging.basicConfig(level=logging.DEBUG)

if __name__ == '__main__':
  print(f'PID: {os.getpid()}')

  try:
    asyncio.run(main())
  except KeyboardInterrupt:
    print('\n[Interrupted]')
