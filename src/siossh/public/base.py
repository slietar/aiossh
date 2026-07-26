from abc import ABC, abstractmethod
from collections.abc import Container

from ..reader import Readable


class PublicKey[AlgorithmName](ABC):
  @abstractmethod
  def encode(self) -> bytes:
    ...

  @abstractmethod
  def decode_verify(self, algorithm: AlgorithmName, encoded_signature: bytes, data: bytes) -> bool:
    ...

  @classmethod
  @abstractmethod
  def decode(cls, reader: Readable) -> PublicKey:
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
