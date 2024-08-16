from asyncio import Future
from dataclasses import dataclass
from typing import Awaitable, Optional, Protocol, TypeVar

from .error import ProtocolError
from .messages.base import DecodableMessage
from .util import ReadableBytesIO, ReadableBytesIOImpl


T_DecodableMessage = TypeVar('T_DecodableMessage', bound=DecodableMessage)

class MessageFlowRead(Protocol):
  def __call__(self, message_type: type[T_DecodableMessage], /) -> Awaitable[tuple[T_DecodableMessage, bytes]]:
    ...


@dataclass(slots=True)
class MessageFlow:
  future: Optional[Future[tuple[int, bytes]]] = None

  def feed(self, message_id: int, payload: bytes, /):
    if not self.future:
      raise ProtocolError('Not reading')

    self.future.set_result((message_id, payload))

  async def read(self, message_type: type[T_DecodableMessage], /) -> tuple[T_DecodableMessage, bytes]:
    if self.future:
      raise RuntimeError('Already reading')

    self.future = Future()

    message_id, payload = await self.future

    if message_id != message_type.id:
      raise ProtocolError('Unexpected message id')

    message = message_type.decode(ReadableBytesIOImpl(payload[1:]))

    self.future = None
    return message, payload
