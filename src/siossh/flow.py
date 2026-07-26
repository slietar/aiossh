from collections.abc import Generator
from dataclasses import dataclass

from .error import ProtocolError
from .messages.base import Message


@dataclass(slots=True)
class MessageStub:
  payload: bytes

  @property
  def id(self):
    return self.payload[0]

  def decode[T: Message](self, message_type: type[T], /) -> T:
    if self.id != message_type.id:
      raise ProtocolError

    return message_type.decode_payload(self.payload)


type MessageFlow[T] = Generator[None, MessageStub, T]
