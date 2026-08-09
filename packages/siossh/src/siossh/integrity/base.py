from typing import Protocol


class IntegrityVerification(Protocol):
  digest_size: int
  key_size: int

  def build(self, key: bytes) -> None:
    ...

  def start(self, sequence_number: int) -> None:
    ...

  def update(self, data: bytes) -> None:
    ...

  def digest(self) -> bytes:
    ...
