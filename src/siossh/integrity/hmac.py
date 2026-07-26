from typing import Literal, override

from cryptography.hazmat.primitives.hashes import SHA1, SHA256, SHA512
from cryptography.hazmat.primitives.hmac import HMAC

from ..error import UnreachableError
from ..structures.primitives import encode_uint32
from .base import IntegrityVerification


# See: RFC 4253 Section 6.4

class HMACSHA1IntegrityVerification(IntegrityVerification):
  digest_size: int = 20
  key_size: int = 20

  @override
  def build(self, key: bytes):
    self._key = key

  @override
  def start(self, sequence_number: int):
    self._hmac = HMAC(self._key, SHA1())
    self._hmac.update(encode_uint32(sequence_number))

  @override
  def update(self, data: bytes):
    self._hmac.update(data)

  @override
  def digest(self):
    digest = self._hmac
    del self._hmac
    return digest.finalize()


# See: RFC 6668

class HMACSHA2IntegrityVerification(IntegrityVerification):
  def __init__(self, digest_size: Literal[32, 64]):
    super().__init__()

    self.digest_size = digest_size
    self.key_size = digest_size

  @override
  def build(self, key: bytes):
    self._key = key

  @override
  def start(self, sequence_number: int):
    match self.digest_size:
      case 32:
        hash = SHA256()
      case 64:
        hash = SHA512()
      case _:
        raise UnreachableError

    self._hmac = HMAC(self._key, hash)
    self._hmac.update(encode_uint32(sequence_number))

  @override
  def update(self, data: bytes):
    self._hmac.update(data)

  @override
  def digest(self):
    digest = self._hmac.finalize()
    del self._hmac
    return digest
