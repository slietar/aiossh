from typing import Optional

from .base import PublicKey
from .ecdsa import ECDSAPublicKey
from .ed25519 import ED25519PublicKey
from .rsa import RSAPublicKey


def resolve_public_key(signature_name: str, /) -> Optional[type[PublicKey]]:
  match signature_name:
    case 'ssh-rsa' | 'ssh-sha2-256' | 'rsa-sha2-512':
      return RSAPublicKey
    case 'ssh-ed25519':
      return ED25519PublicKey
    case 'ecdsa-sha2-nistp256' | 'ecdsa-sha2-nistp384' | 'ecdsa-sha2-nistp521':
      return ECDSAPublicKey
    case _:
      return None
