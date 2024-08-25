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
from asyncio.subprocess import Process
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

import aiodrive
import dexc
from aiodrive import Pool

dexc.install()


@dataclass(slots=True)
class Session:
  _master_fd: int = field(repr=False)
  process: Process
  reader: asyncio.StreamReader

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
    preexec_fn=os.setsid,
    stderr=slave_fd,
    stdin=slave_fd,
    stdout=slave_fd
  )

  try:
    os.close(slave_fd)

    reader = await get_reader(os.fdopen(master_fd, mode='rb'))

    session = Session(master_fd, process, reader)
    session.resize(terminal_size)

    async with until(session.process.wait()):
      yield session
  finally:
    if process.returncode is None:
      process.kill()

    await process.wait()
    print(f'Process exited with code {process.returncode}')


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


async def listen_signal(sig: signal.Signals, /):
  event = asyncio.Event()

  loop = asyncio.get_event_loop()
  loop.add_signal_handler(sig, event.set)

  try:
    while True:
      await event.wait()
      event.clear()

      yield
  finally:
    loop.remove_signal_handler(sig)

async def wait_signal(sig: signal.Signals, /):
  async for _ in listen_signal(sig):
    break

@contextlib.asynccontextmanager
async def until(coro, /):
  # Note: Breaks syntax highlighting

  context_task = asyncio.current_task()
  assert context_task is not None

  cancelled = False

  async def create_coro_task():
    nonlocal cancelled

    await coro

    cancelled = True
    context_task.cancel()

  coro_task = asyncio.create_task(create_coro_task())

  try:
    yield
  except asyncio.CancelledError:
    if cancelled:
      context_task.uncancel()
      cancelled = False

    if context_task.cancelling() > 0:
      raise
  finally:
    # If the above block was not executed because another exception was thrown, and that exception is later caught, asyncio.current_task() needs to be in an non-cancelling state.
    if cancelled:
      context_task.uncancel()

    await aiodrive.cancel_task(coro_task)


async def main():
  # loop = asyncio.get_event_loop()
  # loop.add_signal_handler(signal.SIGWINCH, lambda: print('SIGWINCH'))

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
      async for _ in listen_signal(signal.SIGWINCH):
        session.resize(os.get_terminal_size())

    async with create_session(
      path=Path(os.environ['SHELL']),
      terminal_size=os.get_terminal_size()
    ) as session:
      async with Pool.open() as pool:
        pool.spawn(pipe_pty_to_stdout(session))
        pool.spawn(pipe_stdin_to_pty(session))
        pool.spawn(watch_terminal_size(session))


# import logging
# logging.basicConfig(level=logging.DEBUG)

print(f'PID: {os.getpid()}')

try:
  asyncio.run(main())
except KeyboardInterrupt:
  print('\n[Interrupted]')
