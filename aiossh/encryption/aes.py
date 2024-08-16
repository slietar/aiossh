from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers import Cipher, CipherContext, algorithms, modes


# See: RFC 4344

@dataclass (slots=True)
class AESCTREncryption:
  cipher: Cipher
  decryptor: CipherContext

  def __init__(self, key: bytes, iv: bytes):
    self.cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    self.decryptor = self.cipher.decryptor()

  def block_size(self):
    return 16

  def decrypt(self, data: bytes):
    assert len(data) % self.block_size() == 0
    # decryptor = self.cipher.decryptor()
    return self.decryptor.update(data)
