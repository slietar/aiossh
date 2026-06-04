from dataclasses import dataclass
from typing import Literal, override

from cryptography.hazmat.primitives.asymmetric.x25519 import (
  X25519PrivateKey,
  X25519PublicKey,
)
from cryptography.hazmat.primitives.hashes import Hash
from cryptography.hazmat.primitives.serialization import (
  Encoding,
  PublicFormat,
)

from ..error import ProtocolError
from ..flow import MessageFlow
from ..messages.key_exchange import KexEcdhInitMessage, KexEcdhReplyMessage
from ..public.ecdsa import get_hash_from_curve_size
from ..structures.primitives import encode_mpint, encode_string
from .base import KeyExchange


# See: RFC 8731

@dataclass(slots=True)
class Curve25519KeyExchange(KeyExchange):
  hash_name: Literal['sha256', 'sha512']

  @override
  def hash(self, data: bytes, /) -> bytes:
    match self.hash_name:
      case 'sha256':
        hash_class = get_hash_from_curve_size(256)
      case 'sha512':
        hash_class = get_hash_from_curve_size(512)
      case _:
        raise ValueError('Unsupported hash name')

    digest = Hash(hash_class)
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

    try:
      client_public_key = X25519PublicKey.from_public_bytes(kex_ecdh_init.q_h)
    except ValueError as e:
      raise ProtocolError from e

    private_key = X25519PrivateKey.generate()

    server_public_key_string = private_key.public_key().public_bytes(
      encoding=Encoding.Raw,
      format=PublicFormat.Raw,
    )

    shared_key = private_key.exchange(client_public_key)

    encoded_host_public_key = host_key.to_public_key().encode()

    exchange_hash = self.hash(
      hash_header
      + encode_string(encoded_host_public_key)
      + encode_string(kex_ecdh_init.q_h)
      + encode_string(server_public_key_string)
      + encode_mpint(int.from_bytes(shared_key)),
    )

    signature = host_key.sign_encode(
      algorithm_selection.server_host_key_algorithm,
      exchange_hash,
    )

    conn._send_message(
      KexEcdhReplyMessage(
        k_s=encoded_host_public_key,
        q_s=server_public_key_string,
        signature=signature,
      ),
    )

    return exchange_hash, shared_key
