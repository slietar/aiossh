from collections.abc import Callable

from ..algorithms import (
  EncryptionAlgorithmName,
  MacAlgorithmName,
  is_encryption_algorithm_aead,
)
from ..error import UnreachableError
from ..handler import ChaCha20Poly1305Handler, DefaultHandler, Handler
from ..integrity.resolve import resolve_integrity_verification
from .aes import AES128CTREncryption, AES192CTREncryption, AES256CTREncryption
from .base import Encryption


def resolve_encryption(name: EncryptionAlgorithmName, /) -> type[Encryption]:
  match name:
    case 'aes128-ctr':
      return AES128CTREncryption
    case 'aes192-ctr':
      return AES192CTREncryption
    case 'aes256-ctr':
      return AES256CTREncryption
    case _:
      raise UnreachableError


def build_handler(
  encryption_name: EncryptionAlgorithmName,
  integrity_verification_name: MacAlgorithmName,
  derive_key: Callable[[bytes, int], bytes],
  input_mode: bool,
) -> Handler:
  if is_encryption_algorithm_aead(encryption_name):
    return ChaCha20Poly1305Handler(
      key=derive_key(b'C' if input_mode else b'D', 64),
    )
  else:
    ResolvedEncryption = resolve_encryption(encryption_name)

    encryption = ResolvedEncryption(
      key=derive_key(b'C' if input_mode else b'D', ResolvedEncryption.key_size()),
      iv=derive_key(b'A' if input_mode else b'B', ResolvedEncryption.block_size()),
    )

    integrity_verification = resolve_integrity_verification(integrity_verification_name)

    integrity_verification.build(
      derive_key(b'E' if input_mode else b'F', integrity_verification.key_size),
    )

    return DefaultHandler(
      encryption=encryption,
      integrity_verification=integrity_verification,
    )
