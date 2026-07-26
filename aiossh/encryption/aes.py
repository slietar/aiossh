from dataclasses import dataclass
from typing import override

from cryptography.hazmat.primitives.ciphers import (
  Cipher,
  CipherContext,
  algorithms,
  modes,
)

from .base import Encryption


# See: RFC 4344

@dataclass(slots=True)
class AESCTREncryption(Encryption):
  cipher: Cipher
  decryptor: CipherContext
  encryptor: CipherContext

  @override
  def __init__(self, key: bytes, iv: bytes):
    self.cipher = Cipher(algorithms.AES(key), modes.CTR(iv))

    self.decryptor = self.cipher.decryptor()
    self.encryptor = self.cipher.encryptor()

  @override
  def decrypt_blocks(self, data: bytes, /):
    assert len(data) % self.block_size() == 0
    return self.decryptor.update(data)

  @override
  def encrypt_blocks(self, data: bytes, /):
    assert len(data) % self.block_size() == 0
    return self.encryptor.update(data)

  @override
  @staticmethod
  def block_size():
    return 16


class AES128CTREncryption(AESCTREncryption):
  @override
  @staticmethod
  def key_size():
    return 16

class AES192CTREncryption(AESCTREncryption):
  @override
  @staticmethod
  def key_size():
    return 24

class AES256CTREncryption(AESCTREncryption):
  @override
  @staticmethod
  def key_size():
    return 32
