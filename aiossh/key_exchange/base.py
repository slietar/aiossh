from abc import ABC
from typing import TYPE_CHECKING

from ..algorithms import AlgorithmSelection
from ..flow import MessageFlow
from ..public.base import PrivateKey


if TYPE_CHECKING:
  from ..connection import Connection


class KeyExchange(ABC):
  def hash(self, data: bytes, /) -> bytes:
    ...

  def run_as_server(
    self,
    conn: Connection,
    algorithm_selection: AlgorithmSelection,
    host_key: PrivateKey,
    hash_header: bytes,
  ) -> MessageFlow[tuple[bytes, bytes]]:
    ...
