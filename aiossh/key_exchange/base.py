from collections.abc import Awaitable, Generator
from typing import TYPE_CHECKING, Protocol

from ..public.base import PrivateKey


if TYPE_CHECKING:
  from ..connection import Connection


class KeyExchange(Protocol):
  def hash(self, data: bytes, /) -> bytes:
    ...

  def run(self, conn: Connection, read, client_kex_init_payload: bytes, server_kex_init_payload: bytes) -> Awaitable[tuple[bytes, bytes]]:
    ...
