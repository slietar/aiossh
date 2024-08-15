from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


@dataclass(slots=True)
class AESCTREncryption:
  cipher: Cipher

  def __init__(self, key: bytes, iv: bytes):
    self.cipher = Cipher(algorithms.AES(key), modes.CTR(iv))

  def block_size(self):
    return 16

  def decrypt(self, data: bytes):
    decryptor = self.cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()
