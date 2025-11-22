from typing import Literal, override

from umac import UMAC

from ..structures.primitives import encode_uint64
from .base import IntegrityVerification


# See: draft-miller-secsh-umac-01

class UMACIntegrityVerification(IntegrityVerification):
  digest_size: int
  key_size: int

  def __init__(self, digest_size: Literal[4, 8, 12, 16]):
    super().__init__()

    self.digest_size = digest_size
    self.key_size = 16

  @override
  def build(self, key: bytes):
    self._key = key

  @override
  def start(self, sequence_number: int):
    self._umac = UMAC(self.digest_size, self._key, nonce=encode_uint64(sequence_number))

  @override
  def update(self, data: bytes):
    self._umac.update(data)

  @override
  def digest(self):
    digest = self._umac.digest()
    del self._umac
    return digest
