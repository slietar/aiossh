from .base import Encryption
from ..error import UnreachableError
from .aes import AES128CTREncryption, AES192CTREncryption, AES256CTREncryption


def resolve_encryption(name: str, /) -> type[Encryption]:
  match name:
    case 'aes128-ctr':
      return AES128CTREncryption
    case 'aes192-ctr':
      return AES192CTREncryption
    case 'aes256-ctr':
      return AES256CTREncryption
    case _:
      raise UnreachableError
