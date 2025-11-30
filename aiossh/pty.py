import array
import asyncio
import contextlib
import fcntl
import os
import pty
import signal
import sys
import termios
import tty
from asyncio import StreamReader, StreamReaderProtocol, StreamWriter, TaskGroup
from asyncio.subprocess import Process
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

import aiodrive


@dataclass(slots=True)
class Session:
  _master_fd: int = field(repr=False)
  process: Process
  reader: StreamReader

  def resize(self, size: os.terminal_size, /):
    buf = array.array('H', [size.lines, size.columns, 0, 0])
    fcntl.ioctl(self._master_fd, termios.TIOCSWINSZ, buf)

  def write(self, data: bytes, /):
    os.write(self._master_fd, data)

@contextlib.asynccontextmanager
async def create_session(path: Path, terminal_size: os.terminal_size):
  master_fd, slave_fd = pty.openpty()

  process = await asyncio.create_subprocess_shell(
    # 'echo Start && sleep 10 && echo Stop',
    str(path),
    cwd=os.environ['HOME'],
    start_new_session=True,
    stderr=slave_fd,
    stdin=slave_fd,
    stdout=slave_fd,
  )

  print(f'Internal PID: {process.pid}')
  print('----')

  try:
    os.close(slave_fd)

    reader = await get_reader(os.fdopen(master_fd, mode='rb'))

    session = Session(master_fd, process, reader)
    session.resize(terminal_size)

    class ProcessTerminated(Exception):
      pass

    async def wait():
      await session.process.wait()
      raise ProcessTerminated

    with aiodrive.suppress(ProcessTerminated):
      async with aiodrive.contextualize(wait()):
        yield session
  finally:
    if process.returncode is None:
      process.kill()

    await process.wait()
    print('----')
    print(f'Process exited with code {process.returncode}')


async def get_reader(file: IO[bytes], /):
  reader = StreamReader()
  protocol = StreamReaderProtocol(reader)

  loop = asyncio.get_event_loop()
  await loop.connect_read_pipe(lambda: protocol, file)

  return reader

async def get_writer(file: IO[bytes], /):
  loop = asyncio.get_event_loop()
  transport, protocol = await loop.connect_write_pipe(asyncio.streams.FlowControlMixin, file)

  return StreamWriter(transport, protocol, None, loop)


@contextlib.contextmanager
def unbuffered_tty(file: IO[bytes], /):
  fd = file.fileno()
  attr = termios.tcgetattr(fd)
  tty.setcbreak(fd, termios.TCSANOW)

  try:
    yield
  finally:
    termios.tcsetattr(fd, termios.TCSANOW, attr)

async def iter_reader(reader: StreamReader, /, *, chunk_size: int = 65_536):
  while True:
    chunk = await reader.read(chunk_size)

    if not chunk:
      break

    yield chunk


async def main():
  with unbuffered_tty(sys.stdin.buffer):
    stdin = await get_reader(sys.stdin.buffer)
    stdout = await get_writer(sys.stdout.buffer)

    async def pipe_stdin_to_pty(session: Session):
      async for chunk in iter_reader(stdin):
        session.write(chunk)

    async def pipe_pty_to_stdout(session: Session):
      async for chunk in iter_reader(session.reader):
        stdout.write(chunk)

    async def watch_terminal_size(session: Session):
      while True:
        await aiodrive.wait_for_signal(signal.SIGWINCH)
        session.resize(os.get_terminal_size())

    async with create_session(
      path=Path(os.environ['SHELL']),
      terminal_size=os.get_terminal_size(),
    ) as session:
      async with TaskGroup() as group:
        group.create_task(pipe_pty_to_stdout(session))
        group.create_task(pipe_stdin_to_pty(session))
        group.create_task(watch_terminal_size(session))


# import logging
# logging.basicConfig(level=logging.DEBUG)

print(f'PID: {os.getpid()}')

try:
  asyncio.run(main())
except KeyboardInterrupt:
  print('\n[Interrupted]')
