from asyncio import Lock
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Optional, Protocol, override

import aiodrive


class AsyncReadableStreamProtocol(Protocol):
  # Does not allow for parallel reads

  __slots__ = ()

  # Still using -1 as the default for compatibility with StreamReader
  async def read(self, byte_count: int = -1, /) -> bytes:
    ...

@dataclass(slots=True)
class AsyncReadableStreamImpl(AsyncReadableStreamProtocol):
  _closed: bool = field(default=False, init=False)
  _buffer: bytes = field(default=b'', init=False)
  _button: aiodrive.Button = field(default_factory=aiodrive.Button, init=False)
  _reading: bool = field(default=False, init=False)

  def _close(self):
    self._closed = True
    self._button.press()

  def _feed(self, chunk: bytes, /):
    self._buffer += chunk
    self._button.press()

  @override
  async def read(self, byte_count = -1, /):
    assert not self._reading
    self._reading = True

    try:
      if byte_count < 0:
        while not self._closed:
          await self._button

        data = self._buffer
        self._buffer = b''
      else:
        if not self._buffer:
          await self._button

        data = self._buffer[:byte_count]
        self._buffer = self._buffer[byte_count:]
    finally:
      self._reading = False

    return data


class AsyncWritableStreamProtocol(Protocol):
  # Allows for parallel writes - they will all end at the same time

  __slots__ = ()

  async def write(self, chunk: bytes, /) -> None:
    ...

@dataclass(slots=True)
class AsyncWritableStreamImpl(AsyncWritableStreamProtocol):
  _write: Callable[[Optional[bytes]], Awaitable[None]]

  _buffer: bytes = field(default=b'', init=False)
  _closed: bool = field(default=False, init=False)
  _lock: Lock = field(default_factory=Lock, init=False)

  async def close(self):
    assert not self._closed
    self._closed = True

    async with self._lock:
      await self._write(None)

  @override
  async def write(self, chunk: bytes, /) -> None:
    assert not self._closed

    async with self._lock:
      await self._write(chunk)
