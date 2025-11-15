import logging
from typing import override

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import ssh_key_fingerprint

from .abstract.client import Client
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
    authorized_fingerprints = {
      # bytes.fromhex('c38c25d4546c4df46cec8735b16c31982e9272257b631e41764bfc1bd388eef8'),
      b'',
    }

    fingerprint = ssh_key_fingerprint(key, hash_algorithm=SHA256())

    if fingerprint not in authorized_fingerprints:
      logger.debug(f'Public key authentication failed for user "{user_name}" with public key fingerprint {fingerprint.hex(':')}')
      return False

    return False
