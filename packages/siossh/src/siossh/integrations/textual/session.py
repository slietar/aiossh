import asyncio
import contextlib
import functools
import logging
from dataclasses import dataclass, field
from typing import Optional, cast

from siossh.events import SessionShellEvent, Stream

from textual.app import App
from textual.driver import Driver

from .driver import SSHDriver


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class TextualSession:
  """
  Runs a Textual `App` in-process, wiring its input/output to an SSH channel's `Stream`
  via `SSHDriver` rather than spawning a subprocess in a real pty.
  """

  queue: asyncio.Queue[bytes] = field(default_factory=asyncio.Queue, init=False)
  driver: Optional[SSHDriver] = field(default=None, init=False)
  driver_ready: asyncio.Event = field(default_factory=asyncio.Event, init=False)
  stream: Optional[Stream] = field(default=None, init=False)

  event_trigger: asyncio.Event
  send_trigger: asyncio.Event

  def recv_stdin(self, chunk: bytes):
    self.queue.put_nowait(chunk)

  def recv_stdin_eof(self):
    self.queue.shutdown()

  def set_terminal_size(self, columns: int, rows: int):
    if self.driver is not None:
      self.driver.resize(columns, rows)

  def write(self, data: bytes):
    assert self.stream is not None

    self.stream.write(data)
    self.send_trigger.set()

  async def _pipe_stdin(self):
    await self.driver_ready.wait()
    assert self.driver is not None

    while True:
      try:
        chunk = await self.queue.get()
      except asyncio.QueueShutDown:
        break

      self.driver.feed(chunk)

  async def start(self, event: SessionShellEvent, app: App):
    assert event.pty is not None

    app.driver_class = cast(type[Driver], functools.partial(SSHDriver, session=self))

    self.stream = event.accept()

    self.event_trigger.set()
    self.send_trigger.set()

    pipe_task = asyncio.create_task(self._pipe_stdin())

    try:
      await app.run_async(mouse=True, size=event.pty.window_chars)
    finally:
      pipe_task.cancel()

      with contextlib.suppress(asyncio.CancelledError):
        await pipe_task

    LOGGER.debug('Textual app exited')

    self.stream.exit(0)
    self.send_trigger.set()
