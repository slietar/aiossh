import array
import asyncio
import contextlib
import fcntl
import os
import pty
import subprocess
import sys
import termios
import tty
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import IO, Optional

import dexc
from aiodrive import Pool

dexc.install()


@dataclass(slots=True)
class Session:
  _master_fd: int = field(repr=False)
  reader: asyncio.StreamReader

  def resize(self, size: os.terminal_size, /):
    buf = array.array('H', [size.lines, size.columns, 0, 0])
    fcntl.ioctl(self._master_fd, termios.TIOCSWINSZ, buf)

async def create_session(path: Path, terminal_size: os.terminal_size):
  master_fd, slave_fd = pty.openpty()

  process = subprocess.Popen(
    [str(path)],
    close_fds=True,
    cwd=os.environ['HOME'],
    preexec_fn=os.setsid,
    shell=True,
    stderr=slave_fd,
    stdin=slave_fd,
    stdout=slave_fd,
    universal_newlines=True
  )

  os.close(slave_fd)

  reader = await get_reader(os.fdopen(master_fd, mode='rb'))
  # writer = await get_writer(os.fdopen(master_fd, mode='wb'))

  session = Session(master_fd, reader)
  session.resize(terminal_size)

  return session


async def get_reader(file: IO[bytes], /):
  reader = asyncio.StreamReader()
  protocol = asyncio.StreamReaderProtocol(reader)

  loop = asyncio.get_event_loop()
  await loop.connect_read_pipe(lambda: protocol, file)

  return reader

async def get_writer(file: IO[bytes], /):
  loop = asyncio.get_event_loop()
  transport, protocol = await loop.connect_write_pipe(asyncio.streams.FlowControlMixin, file)

  writer = asyncio.StreamWriter(transport, protocol, None, loop)
  return writer


@contextlib.contextmanager
def unbuffered_tty(file: IO[bytes], /):
  fd = file.fileno()
  attr = termios.tcgetattr(fd)
  tty.setcbreak(fd, termios.TCSANOW)

  try:
    yield
  finally:
    termios.tcsetattr(fd, termios.TCSANOW, attr)

async def iter_reader(reader: asyncio.StreamReader, /, *, chunk_size: int = 65_536):
  while True:
    chunk = await reader.read(chunk_size)

    if not chunk:
      break

    yield chunk


async def main():
  with unbuffered_tty(sys.stdin.buffer):
    stdin = await get_reader(sys.stdin.buffer)
    stdout = await get_writer(sys.stdout.buffer)

    async def pipe_stdin(session):
      await asyncio.sleep(0.1)

      while True:
        chunk = await stdin.read(256)
        session.write(chunk)

    async with Pool.open() as pool:
      session = await create_session(
        path=Path(os.environ['SHELL']),
        terminal_size=os.get_terminal_size()
      )

      async for x in iter_reader(session.reader):
        print(repr(x))

      # pool.spawn(pipe_stdin(session))

      # async for data in session:
      #   stdout.write(data)

      print('Done 1')

    print('Done 2')


# import logging
# logging.basicConfig(level=logging.DEBUG)

print(f'PID: {os.getpid()}')

try:
  asyncio.run(main())
except KeyboardInterrupt:
  print('\n[Interrupted]')
