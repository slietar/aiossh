from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers import Cipher, CipherContext, algorithms, modes

from .base import Encryption


# See: RFC 4344

@dataclass(slots=True)
class AESCTREncryption(Encryption):
  cipher: Cipher
  decryptor: CipherContext

  def __init__(self, key: bytes, iv: bytes):
    self.cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    self.decryptor = self.cipher.decryptor()

  @staticmethod
  def block_size():
    return 16

  def decrypt_blocks(self, data: bytes, /):
    assert len(data) % self.block_size() == 0
    # decryptor = self.cipher.decryptor()
    return self.decryptor.update(data)


class AES128CTREncryption(AESCTREncryption):
  @staticmethod
  def key_size():
    return 16

class AES192CTREncryption(AESCTREncryption):
  @staticmethod
  def key_size():
    return 24

class AES256CTREncryption(AESCTREncryption):
  @staticmethod
  def key_size():
    return 32
