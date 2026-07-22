from abc import ABC, abstractmethod


class BlockEncryption(ABC):
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


class AEADEncryption(ABC):
  @abstractmethod
  def __init__(self, key: bytes):
    ...

  @abstractmethod
  def decrypt_length(self, sequence_number: int, encrypted_length: bytes, /) -> bytes:
    ...

  @abstractmethod
  def decrypt_and_verify_packet(
    self,
    sequence_number: int,
    encrypted_length: bytes,
    encrypted_rest: bytes,
    tag: bytes,
    /,
  ) -> bytes:
    # Raises cryptography.exceptions.InvalidSignature on tag mismatch
    ...

  @abstractmethod
  def encrypt_packet(self, sequence_number: int, packet_with_length: bytes, /) -> bytes:
    # Returns the complete wire bytes for this packet: encrypted length +
    # encrypted rest + trailing tag
    ...

  @staticmethod
  @abstractmethod
  def block_size() -> int:
    # Used only for encode_packet()'s padding-alignment argument, not a real
    # block cipher block size.
    ...

  @staticmethod
  @abstractmethod
  def key_size() -> int:
    ...

  @staticmethod
  @abstractmethod
  def tag_size() -> int:
    ...


type Encryption = BlockEncryption | AEADEncryption
