from typing import Protocol


class Encryption(Protocol):
  def __init__(self, key: bytes, iv: bytes):
    ...

  @staticmethod
  def block_size() -> int:
    ...

  @staticmethod
  def key_size() -> int:
    ...

  def decrypt_blocks(self, data: bytes, /) -> bytes:
    ...
