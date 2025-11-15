import asyncio
from asyncio import Event, Future
from collections.abc import Awaitable
from dataclasses import dataclass
from typing import Optional, Protocol

from .error import ProtocolError
from .messages.base import DecodableMessage
from .util import ReadableBytesIOImpl


class MessageFlowRead(Protocol):
  def __call__[T: DecodableMessage](self, message_type: type[T], /) -> Awaitable[tuple[T, bytes]]:
    ...


@dataclass(slots=True)
class MessageFlow:
  event: Optional[Event] = None
  future: Optional[Future[tuple[int, bytes]]] = None

  async def feed(self, message_id: int, payload: bytes, /):
    if self.future is None:
      raise ProtocolError('Not reading')

    self.future.set_result((message_id, payload))
    await self.future

    self.event = Event()
    await self.event.wait()

  async def read[T: DecodableMessage](self, message_type: type[T], /) -> tuple[T, bytes]:
    if self.future is not None:
      raise RuntimeError('Already reading')

    future = Future()
    self.future = future

    message_id, payload = await asyncio.shield(future)
    self.future = None

    assert self.event is not None
    self.event.set()
    self.event = None

    if message_id != message_type.id:
      raise ProtocolError('Unexpected message id')

    with ReadableBytesIOImpl(payload[1:]) as reader:
      message = message_type.decode(reader)

    return message, payload
