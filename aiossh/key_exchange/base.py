from collections.abc import Awaitable
from typing import TYPE_CHECKING, Protocol

from ..flow import MessageFlowRead


if TYPE_CHECKING:
  from ..connection import Connection


class KeyExchange(Protocol):
  def hash(self, data: bytes, /) -> bytes:
    ...

  def run(self, conn: Connection, read: MessageFlowRead, client_kex_init_payload: bytes, server_kex_init_payload: bytes) -> Awaitable[tuple[bytes, bytes]]:
    ...
