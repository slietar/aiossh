import array
import asyncio
import fcntl
import os
import subprocess
import sys
import termios
from typing import Optional

from aiodrive import Pool


class Session:
  def __init__(self, size: os.terminal_size):
    self._master = None
    self._proc = None
    self._size = size

  @property
  def status(self):
    return self._proc.poll()

  def resize(self, new_size: Optional[os.terminal_size] = None):
    if new_size:
      self._size = new_size

    buf = array.array('H', [self._size.lines, self._size.columns, 0, 0])
    fcntl.ioctl(self._master, termios.TIOCSWINSZ, buf)

  async def start(self):
    import pty

    master, slave = pty.openpty()
    self._master = master

    self._proc = subprocess.Popen(["fish"], stdout=slave, stderr=slave, stdin=slave, universal_newlines=True, preexec_fn=os.setsid, shell=True, close_fds=True, cwd=os.environ["HOME"])

    os.close(slave)

    self.resize()

    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, os.fdopen(master, mode="rb"))

    while self._proc.poll() is None:
      data = await reader.read(100)

      # 'data' is an empty bytes object when the process terminates.
      if len(data) > 0:
        yield data

    # print(res.decode("utf-8"), end="")

  def close(self):
    self._proc.kill()

  def write(self, data):
    os.write(self._master, data)


async def get_stdin_reader():
  reader = asyncio.StreamReader()
  protocol = asyncio.StreamReaderProtocol(reader)

  loop = asyncio.get_event_loop()
  await loop.connect_read_pipe(lambda: protocol, sys.stdin)

  return reader


async def main():
  session = Session(os.get_terminal_size())
  stdin = await get_stdin_reader()

  async def pipe_stdin():
    await asyncio.sleep(0.1)

    async for chunk in stdin:
      session.write(chunk)

  async with Pool.open() as pool:
    pool.spawn(pipe_stdin())

    async for data in session.start():
      sys.stdout.buffer.write(data)
      sys.stdout.buffer.flush()

asyncio.run(main())
