from ..error import UnreachableError
from .base import KeyExchange
from .dh import DhKeyExchange
from .ecdh import EcdhKeyExchange


def resolve_key_exchange(name: str, /) -> type[KeyExchange]:
  match name:
    case 'diffie-hellman-group-exchange-sha256':
      return DhKeyExchange
    case 'ecdh-sha2-nistp256':
      return EcdhKeyExchange
    case _:
      raise UnreachableError
