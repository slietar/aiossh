from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, hmac


# See: RFC 6668

@dataclass(slots=True)
class HMACSHA256IntegrityVerification:
  key: bytes

  def __init__(self, key: bytes):
    self.key = key

  def verify(self, data: bytes):
    hash = hmac.HMAC(self.key, hashes.SHA256())
    hash.update(data)
    # hash.verify(signature)
    return hash.finalize()

  @staticmethod
  def key_size():
    return 32

  @staticmethod
  def digest_size():
    return 32


@dataclass(slots=True)
class HMACSHA1IntegrityVerification:
  key: bytes

  def __init__(self, key: bytes):
    self.key = key

  def verify(self, data: bytes):
    hash = hmac.HMAC(self.key, hashes.SHA1())
    hash.update(data)
    # hash.verify(signature)
    return hash.finalize()

  @staticmethod
  def key_size():
    return 20

  @staticmethod
  def digest_size():
    return 20
