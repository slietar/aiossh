from dataclasses import dataclass
from typing import override

from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
  X25519PrivateKey,
  X25519PublicKey,
)
from cryptography.hazmat.primitives.hashes import SHA256, Hash
from cryptography.hazmat.primitives.serialization import (
  Encoding,
  PublicFormat,
)

from ..error import ProtocolError
from ..flow import MessageFlow
from ..messages.key_exchange import KexEcdhInitMessage, KexEcdhReplyMessage
from ..structures.primitives import encode_string
from .base import KeyExchange


# See: draft-ietf-sshm-mlkem-hybrid-kex

MLKEM768_PUBLIC_KEY_SIZE = 1184
X25519_PUBLIC_KEY_SIZE = 32


@dataclass(slots=True)
class MlKem768X25519KeyExchange(KeyExchange):
  @override
  def hash(self, data: bytes, /) -> bytes:
    digest = Hash(SHA256())
    digest.update(data)

    return digest.finalize()

  @override
  def run_as_server(
    self,
    conn,
    algorithm_selection,
    host_key,
    hash_header,
  ) -> MessageFlow[tuple[bytes, bytes]]:
    kex_ecdh_init = (yield).decode(KexEcdhInitMessage)
    q_c = kex_ecdh_init.q_h

    if len(q_c) != (MLKEM768_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE):
      raise ProtocolError

    mlkem_client_public_key_bytes = q_c[:MLKEM768_PUBLIC_KEY_SIZE]
    x25519_client_public_key_bytes = q_c[MLKEM768_PUBLIC_KEY_SIZE:]

    try:
      mlkem_client_public_key = MLKEM768PublicKey.from_public_bytes(mlkem_client_public_key_bytes)
      x25519_client_public_key = X25519PublicKey.from_public_bytes(x25519_client_public_key_bytes)
    except ValueError as e:
      raise ProtocolError from e

    x25519_private_key = X25519PrivateKey.generate()

    x25519_server_public_key_bytes = x25519_private_key.public_key().public_bytes(
      encoding=Encoding.Raw,
      format=PublicFormat.Raw,
    )

    x25519_shared_secret = x25519_private_key.exchange(x25519_client_public_key)
    mlkem_shared_secret, mlkem_ciphertext = mlkem_client_public_key.encapsulate()

    q_s = mlkem_ciphertext + x25519_server_public_key_bytes
    shared_secret = self.hash(mlkem_shared_secret + x25519_shared_secret)

    # The combined shared secret is already a fixed-size hash output, encoded
    # as an opaque string rather than an mpint.
    encoded_shared_secret = encode_string(shared_secret)

    encoded_host_public_key = host_key.to_public_key().encode()

    exchange_hash = self.hash(
      hash_header
      + encode_string(encoded_host_public_key)
      + encode_string(q_c)
      + encode_string(q_s)
      + encoded_shared_secret,
    )

    signature = host_key.sign_encode(
      algorithm_selection.server_host_key_algorithm,
      exchange_hash,
    )

    conn._send_message(
      KexEcdhReplyMessage(
        k_s=encoded_host_public_key,
        q_s=q_s,
        signature=signature,
      ),
    )

    return exchange_hash, encoded_shared_secret
