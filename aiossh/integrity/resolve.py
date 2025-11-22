from ..algorithms import MacAlgorithmName
from ..error import UnreachableError
from .base import IntegrityVerification
from .hmac import HMACSHA1IntegrityVerification, HMACSHA2IntegrityVerification
from .umac import UMACIntegrityVerification


def resolve_integrity_verification(name: MacAlgorithmName) -> IntegrityVerification:
  match name:
    case 'hmac-sha1':
      return HMACSHA1IntegrityVerification()
    case 'hmac-sha2-256':
      return HMACSHA2IntegrityVerification(32)
    case 'hmac-sha2-512':
      return HMACSHA2IntegrityVerification(64)
    case 'umac-32':
      return UMACIntegrityVerification(4)
    case 'umac-64' | 'umac-64@openssh.com':
      return UMACIntegrityVerification(8)
    case 'umac-96':
      return UMACIntegrityVerification(12)
    case 'umac-128' | 'umac-128@openssh.com':
      return UMACIntegrityVerification(16)
    case _:
      raise UnreachableError
