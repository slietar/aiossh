from asyncio import Event
from codecs import getincrementaldecoder
from typing import Any, Optional, Protocol, override

from textual import events
from textual._xterm_parser import XTermParser
from textual.app import App
from textual.driver import Driver
from textual.geometry import Size


class SSHDriverSession(Protocol):
  """The subset of a session's interface that `SSHDriver` needs to feed input and queue output."""

  driver: Optional[SSHDriver]
  driver_ready: Event

  def write(self, data: bytes) -> None:
    ...


class SSHDriver(Driver):
  """
  A Textual driver that reads/writes an SSH channel's `Stream` instead of a real tty.

  Textual normally drives a real terminal by reading raw bytes from stdin and writing
  ANSI escape sequences to stdout. Here, those bytes flow through an SSH channel instead:
  incoming channel data is fed to this driver via `feed()`, and outgoing writes are queued
  onto the session via `write()`.
  """

  def __init__(self, app: App[Any], *, session: SSHDriverSession, debug: bool = False, mouse: bool = True, size: Optional[tuple[int, int]] = None):
    super().__init__(app, debug=debug, mouse=mouse, size=size)

    self._session = session
    session.driver = self
    session.driver_ready.set()

    self._parser = XTermParser(debug=False)
    self._decode = getincrementaldecoder('utf-8')().decode

  def feed(self, data: bytes):
    for event in self._parser.feed(self._decode(data)):
      self.process_message(event)

  def resize(self, columns: int, rows: int):
    self._size = (columns, rows)

    size = Size(columns, rows)
    self._app.post_message(events.Resize(size, size))

  @override
  def write(self, data: str) -> None:
    self._session.write(data.encode())

  def _enable_mouse_support(self):
    if not self._mouse:
      return

    write = self.write
    write('\x1b[?1000h')
    write('\x1b[?1003h')
    write('\x1b[?1015h')
    write('\x1b[?1006h')

  def _disable_mouse_support(self):
    if not self._mouse:
      return

    write = self.write
    write('\x1b[?1000l')
    write('\x1b[?1003l')
    write('\x1b[?1015l')
    write('\x1b[?1006l')

  def _enable_bracketed_paste(self):
    self.write('\x1b[?2004h')

  def _disable_bracketed_paste(self):
    self.write('\x1b[?2004l')

  @override
  def start_application_mode(self):
    width, height = self._size or (80, 24)
    size = Size(width, height)

    self._app.post_message(events.Resize(size, size))

    self.write('\x1b[?1049h')  # Alt screen
    self._enable_mouse_support()
    self.write('\x1b[?25l')  # Hide cursor
    self.write('\x1b[?1004h')  # Enable FocusIn/FocusOut
    self._enable_bracketed_paste()
    self.flush()

  @override
  def disable_input(self):
    pass

  @override
  def stop_application_mode(self):
    self._disable_bracketed_paste()
    self._disable_mouse_support()

    self.write('\x1b[?1049l')  # Alt screen off
    self.write('\x1b[?25h')  # Show cursor
    self.write('\x1b[?1004l')  # Disable FocusIn/FocusOut
    self.flush()
