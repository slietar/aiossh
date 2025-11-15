import logging
from typing import override

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import ssh_key_fingerprint

from .abstract.client import Client
from .error import UnreachableError
from .messages.user_auth import AuthenticationMethodName
from .tcp import SockName


logger = logging.getLogger(__name__)


class ExampleClient(Client):
  def __init__(self, socket_name: SockName):
    logger.debug(f'New connection from {socket_name}')

  @override
  async def get_auth_methods(self, user_name) -> set[AuthenticationMethodName]:
    return {'publickey'}

  @override
  async def auth_with_public_key(self, user_name, key, *, in_use) -> bool:
    match key:
      case Ed25519PublicKey():
        key_type = 'ED25519'
      case RSAPublicKey():
        key_type = 'RSA'
      case _:
        raise UnreachableError

    authorized_fingerprints = {
      bytes.fromhex(string.replace(':', '')) for string in {
        # ED25519
        'c3:8c:25:d4:54:6c:4d:f4:6c:ec:87:35:b1:6c:31:98:2e:92:72:25:7b:63:1e:41:76:4b:fc:1b:d3:88:ee:f8',

        # RSA
        '90:60:a3:72:6b:2f:bf:db:7f:16:54:d5:a1:f3:cb:da:a0:6b:bb:ba:79:5e:35:1c:ef:46:66:26:e5:c7:72:b9',
      }
    }

    fingerprint = ssh_key_fingerprint(key, hash_algorithm=SHA256())

    if fingerprint in authorized_fingerprints:
      if in_use:
        logger.debug(f'Authenticated user "{user_name}" with public {key_type} key fingerprint {fingerprint.hex(':')}')

      return True
    else:
      logger.debug(f'Public key authentication failed for user "{user_name}" with public {key_type} key fingerprint {fingerprint.hex(':')}')
      return False
