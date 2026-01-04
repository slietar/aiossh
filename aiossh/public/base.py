from abc import ABC, abstractmethod
from collections.abc import Container

from ..util import ReadableBytesIO


class PublicKey[AlgorithmName](ABC):
  @abstractmethod
  def encode(self) -> bytes:
    ...

  @abstractmethod
  def decode_verify(self, algorithm: AlgorithmName, encoded_signature: bytes, data: bytes) -> bool:
    ...

  @classmethod
  @abstractmethod
  def decode(cls, reader: ReadableBytesIO) -> PublicKey:
    ...


class PrivateKey[AlgorithmName](ABC):
  @abstractmethod
  def algorithms(self) -> Container[str]:
    ...

  @abstractmethod
  def sign_encode(self, algorithm: AlgorithmName, data: bytes) -> bytes:
    ...

  @abstractmethod
  def to_public_key(self) -> PublicKey[AlgorithmName]:
    ...
