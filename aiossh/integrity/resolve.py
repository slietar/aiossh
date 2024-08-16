from ..error import UnreachableError
from .base import IntegrityVerification
from .hmac import (HMACSHA1IntegrityVerification,
                   HMACSHA256IntegrityVerification)


def resolve_integrity_verification(name: str, /) -> type[IntegrityVerification]:
  match name:
    case 'hmac-sha1':
      return HMACSHA1IntegrityVerification
    case 'hmac-sha2-256':
      return HMACSHA256IntegrityVerification
    case _:
      raise UnreachableError
