from ..algorithms import EncryptionAlgorithmName
from ..error import UnreachableError
from .aes import AES128CTREncryption, AES192CTREncryption, AES256CTREncryption
from .base import AEADEncryption, BlockEncryption
from .chacha import ChaCha20Poly1305Encryption


def resolve_encryption(name: EncryptionAlgorithmName, /) -> type[BlockEncryption] | type[AEADEncryption]:
  match name:
    case 'aes128-ctr':
      return AES128CTREncryption
    case 'aes192-ctr':
      return AES192CTREncryption
    case 'aes256-ctr':
      return AES256CTREncryption
    case 'chacha20-poly1305' | 'chacha20-poly1305@openssh.com':
      return ChaCha20Poly1305Encryption
    case _:
      raise UnreachableError
