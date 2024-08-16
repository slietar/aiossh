from typing import Protocol


class IntegrityVerification(Protocol):
  def __init__(self, key: bytes):
    ...

  def produce(self, data: bytes, /) -> bytes:
    ...

  @staticmethod
  def digest_size() -> int:
    ...

  @staticmethod
  def key_size() -> int:
    ...
