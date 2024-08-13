from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

from cryptography.hazmat.primitives.asymmetric import ed25519

from .structures.keys import encode_ed25519_public_key


class HostKey(ABC):
  algorithm: ClassVar[str]

  @abstractmethod
  def encode_public_key(self) -> bytes:
    ...

@dataclass(slots=True)
class ED25519HostKey:
  algorithm: ClassVar[str] = 'ssh-ed25519'

  private_key: ed25519.Ed25519PrivateKey

  def encode_public_key(self):
    return encode_ed25519_public_key(self.private_key.public_key())

  def __getstate__(self):
    return self.private_key.private_bytes_raw()

  def __setstate__(self, state: bytes):
    self.private_key = ed25519.Ed25519PrivateKey.from_private_bytes(state)
