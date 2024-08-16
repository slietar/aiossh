from ..error import UnreachableError
from .base import KeyExchange
from .dh import DhKeyExchange


def resolve_key_exchange(name: str, /) -> type[KeyExchange]:
  match name:
    case 'diffie-hellman-group-exchange-sha256':
      return DhKeyExchange
    case _:
      raise UnreachableError
