from ..error import UnreachableError
from .base import KeyExchange
from .curve25519 import Curve25519KeyExchange
from .dh import DhKeyExchange
from .ecdh import EcdhKeyExchange
from .mlkem768x25519 import MlKem768X25519KeyExchange


def resolve_key_exchange(name: str, /) -> KeyExchange:
  match name:
    case 'diffie-hellman-group-exchange-sha256':
      return DhKeyExchange()
    case 'curve25519-sha256':
      return Curve25519KeyExchange('sha256')
    case 'curve25519-sha512':
      return Curve25519KeyExchange('sha512')
    case 'ecdh-sha2-nistp256':
      return EcdhKeyExchange('nistp256')
    case 'ecdh-sha2-nistp384':
      return EcdhKeyExchange('nistp384')
    case 'ecdh-sha2-nistp521':
      return EcdhKeyExchange('nistp521')
    case 'mlkem768x25519-sha256':
      return MlKem768X25519KeyExchange()
    case _:
      raise UnreachableError
