from ..error import UnreachableError
from .base import KeyExchange
from .dh import DhKeyExchange
from .ecdh import EcdhKeyExchange


def resolve_key_exchange(name: str, /) -> KeyExchange:
  match name:
    case 'diffie-hellman-group-exchange-sha256':
      return DhKeyExchange()
    case 'ecdh-sha2-nistp256':
      return EcdhKeyExchange('nistp256')
    case 'ecdh-sha2-nistp384':
      return EcdhKeyExchange('nistp384')
    case 'ecdh-sha2-nistp521':
      return EcdhKeyExchange('nistp521')
    case _:
      raise UnreachableError
