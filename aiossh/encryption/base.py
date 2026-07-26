from abc import ABC, abstractmethod


class Encryption(ABC):
  @abstractmethod
  def __init__(self, key: bytes, iv: bytes):
    ...

  @abstractmethod
  def decrypt_blocks(self, data: bytes, /) -> bytes:
    ...

  @abstractmethod
  def encrypt_blocks(self, data: bytes, /) -> bytes:
    ...

  @staticmethod
  @abstractmethod
  def block_size() -> int:
    # Guaranteed to be at least 8.
    ...

  @staticmethod
  @abstractmethod
  def key_size() -> int:
    ...
