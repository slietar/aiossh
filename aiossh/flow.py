from collections.abc import Awaitable, Generator
from dataclasses import dataclass
from typing import Protocol

from .error import ProtocolError
from .messages.base import Message


@dataclass(slots=True)
class MessageStub:
  _payload: bytes

  @property
  def id(self):
    return self._payload[0]

  def decode[T: Message](self, message_type: type[T], /) -> T:
    if self.id != message_type.id:
      raise ProtocolError

    return message_type.decode_payload(self._payload)


type MessageFlow = Generator[tuple[bytes, bytes], MessageStub, int]
