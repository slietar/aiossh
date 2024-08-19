from asyncio import Event, Future, Lock
import asyncio
from dataclasses import dataclass, field
from typing import Awaitable, Generic, Optional, Protocol, TypeVar

from .error import ProtocolError
from .messages.base import DecodableMessage
from .util import ReadableBytesIO, ReadableBytesIOImpl


T_DecodableMessage = TypeVar('T_DecodableMessage', bound=DecodableMessage)

class MessageFlowRead(Protocol):
  def __call__(self, message_type: type[T_DecodableMessage], /) -> Awaitable[tuple[T_DecodableMessage, bytes]]:
    ...


@dataclass(slots=True)
class MessageFlow:
  event: Optional[Event] = None
  future: Optional[Future[tuple[int, bytes]]] = None

  async def feed(self, message_id: int, payload: bytes, /):
    if not self.future:
      raise ProtocolError('Not reading')

    self.future.set_result((message_id, payload))
    await self.future

    self.event = Event()
    await self.event.wait()

  async def read(self, message_type: type[T_DecodableMessage], /) -> tuple[T_DecodableMessage, bytes]:
    if self.future:
      raise RuntimeError('Already reading')

    self.future = Future()

    message_id, payload = await self.future
    self.future = None

    assert self.event is not None
    self.event.set()
    self.event = None

    if message_id != message_type.id:
      raise ProtocolError('Unexpected message id')

    with ReadableBytesIOImpl(payload[1:]) as reader:
      message = message_type.decode(reader)

    return message, payload
