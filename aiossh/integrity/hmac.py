from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, hmac

from .base import IntegrityVerification


@dataclass(slots=True)
class HMACSHA1IntegrityVerification(IntegrityVerification):
  key: bytes

  def __init__(self, key: bytes):
    self.key = key

  def produce(self, data: bytes, /):
    hash = hmac.HMAC(self.key, hashes.SHA1())
    hash.update(data)
    return hash.finalize()

  @staticmethod
  def digest_size():
    return 20

  @staticmethod
  def key_size():
    return 20


# See: RFC 6668

@dataclass(slots=True)
class HMACSHA256IntegrityVerification(IntegrityVerification):
  key: bytes

  def __init__(self, key: bytes):
    self.key = key

  def produce(self, data: bytes, /):
    hash = hmac.HMAC(self.key, hashes.SHA256())
    hash.update(data)
    return hash.finalize()

  @staticmethod
  def digest_size():
    return 32

  @staticmethod
  def key_size():
    return 32
