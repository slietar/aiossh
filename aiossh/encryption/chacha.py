from dataclasses import dataclass
from typing import override

from cryptography.hazmat.primitives.ciphers import (
  Cipher,
  CipherContext,
  algorithms,
  modes,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .base import Encryption


# See: RFC 4344

@dataclass(slots=True)
class ChaCha20Poly1305Encryption(Encryption):
  cipher: Cipher
  decryptor: CipherContext
  encryptor: CipherContext

  def __init__(self, key: bytes, iv: bytes):
    self.chacha = ChaCha20Poly1305(key)

    self.decryptor = self.cipher.decryptor()
    self.encryptor = self.cipher.encryptor()

  @override
  @staticmethod
  def block_size():
    return 16

  @override
  @staticmethod
  def key_size():
      return 64

  @override
  def decrypt_blocks(self, data: bytes, /):
    assert len(data) % self.block_size() == 0
    return self.decryptor.update(data)

  @override
  def encrypt_blocks(self, data: bytes, /):
    assert len(data) % self.block_size() == 0
    return self.encryptor.update(data)
