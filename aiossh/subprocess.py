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
from abc import ABC, abstractmethod
from asyncio import StreamReader, TaskGroup
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, override

import aiodrive

from .stream import AsyncReadableStreamProtocol
from .terminal_modes import TerminalModes
from .termios_modes import apply_terminal_modes


LOGGER = logging.getLogger(__name__)


class Subprocess(ABC):
  code: Optional[int] = None
  reader: StreamReader
  reader_error: Optional[StreamReader]

  @abstractmethod
  async def write(self, data: bytes, /):
    raise NotImplementedError


@dataclass(slots=True)
class PTYSubprocess(Subprocess):
  _master_fd: int = field(repr=False)
  process: aiodrive.Process
  reader: StreamReader
  reader_error: Optional[StreamReader]

  code: Optional[int] = None

  def resize(self, size: os.terminal_size, /):
    buf = array.array('H', [size.lines, size.columns, 0, 0])
    fcntl.ioctl(self._master_fd, termios.TIOCSWINSZ, buf)

  @override
  async def write(self, data: bytes, /):
    # TODO: Close when receving EOF
    os.write(self._master_fd, data)

  @classmethod
  @contextlib.asynccontextmanager
  async def create(cls, command: str, *, cwd: Path, env: Mapping[str, str], terminal_size: os.terminal_size, terminal_modes: TerminalModes):
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
          apply_terminal_modes(slave_fd, terminal_modes)
          os.close(slave_fd)

          reader = await aiodrive.get_reader(
            os.fdopen(master_fd, mode='rb'),
          )

          session = cls(master_fd, process, reader, reader_error=None)
          session.resize(terminal_size)
        except Exception as e:
          LOGGER.error(f'Failed to setup process + {e}')
        else:
          yield session
    except aiodrive.ProcessTerminatedException as e: # TODO: Use except*
      LOGGER.info(f'Process terminated with code {e.code}')

      if session is not None:
        session.code = e.code & 0xff
    else:
      LOGGER.info('Process exited normally')

      if session is not None:
        session.code = 0


@dataclass(slots=True)
class RegularSubprocess(Subprocess):
  process: aiodrive.Process
  reader: StreamReader
  reader_error: Optional[StreamReader]

  code: Optional[int] = None

  @override
  async def write(self, data: bytes, /):
    if data:
      self.process.stdin.write(data)
      await self.process.stdin.drain()
    else:
      self.process.stdin.close()

  @classmethod
  @contextlib.asynccontextmanager
  async def create(cls, command: str, *, cwd: Path, env: Mapping[str, str]):
    process = await aiodrive.start_process(command, cwd=cwd, env=env)

    async def wait():
      await process.wait(first_signal=signal.SIGTERM)
      raise aiodrive.ProcessTerminatedException(0)

    subprocess = None

    try:
      async with aiodrive.contextualize(wait()):
        subprocess = cls(process, process.stdout, reader_error=process.stderr)
        yield subprocess
    except aiodrive.ProcessTerminatedException as e: # TODO: Use except*
      LOGGER.info(f'Process terminated with code {e.code}')

      if subprocess is not None:
        subprocess.code = e.code & 0xff
    else:
      LOGGER.info('Process exited normally')

      if subprocess is not None:
        subprocess.code = 0


async def iter_reader(reader: AsyncReadableStreamProtocol, /, *, chunk_size: int = 65_536):
  while True:
    chunk = await reader.read(chunk_size)

    if not chunk:
      break

    yield chunk


async def main():
  with aiodrive.set_file_unbuffered(sys.stdin.buffer):
    stdin = await aiodrive.get_reader(sys.stdin.buffer)
    stdout = await aiodrive.get_writer(sys.stdout.buffer)

    async def pipe_stdin_to_pty(session: PTYSubprocess):
      async for chunk in iter_reader(stdin):
        await session.write(chunk)

    async def watch_terminal_size(session: PTYSubprocess):
      while True:
        await aiodrive.wait_for_signal(signal.SIGWINCH)
        session.resize(os.get_terminal_size())

    session = None

    try:
      async with PTYSubprocess.create(
        Path(os.environ['SHELL']).as_posix(),
        cwd=Path.home(),
        env=os.environ,
        terminal_size=os.get_terminal_size(),
        terminal_modes=TerminalModes(),
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
