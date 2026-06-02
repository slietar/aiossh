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
from ..public.ecdsa import get_hash_from_curve_size
from ..structures.primitives import encode_mpint, encode_string
from .base import KeyExchange
from .ecdh import KexEcdhInitMessage, KexEcdhReplyMessage


# See: RFC 8731

@dataclass(slots=True)
class Curve25519KeyExchange(KeyExchange):
  hash_name: Literal['sha256', 'sha512']

  @override
  def hash(self, data: bytes, /):
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
  async def run(
    self,
    conn,
    read,
    client_kex_init_payload,
    server_kex_init_payload,
  ):
    init_message, _ = await read(KexEcdhInitMessage)

    try:
      client_public_key = X25519PublicKey.from_public_bytes(init_message.q_h)
    except ValueError as e:
      raise ProtocolError from e

    private_key = X25519PrivateKey.generate()

    server_public_key_string = private_key.public_key().public_bytes(
      encoding=Encoding.Raw,
      format=PublicFormat.Raw,
    )

    shared_key = private_key.exchange(client_public_key)

    assert conn.host_key is not None
    encoded_host_public_key = conn.host_key.to_public_key().encode()

    assert conn.client_ident_string is not None
    assert conn.server_ident_string is not None

    exchange_hash = self.hash(
        encode_string(bytes(conn.client_ident_string))
      + encode_string(bytes(conn.server_ident_string))
      + encode_string(client_kex_init_payload)
      + encode_string(server_kex_init_payload)
      + encode_string(encoded_host_public_key)
      + encode_string(init_message.q_h)
      + encode_string(server_public_key_string)
      + encode_mpint(int.from_bytes(shared_key)),
    )

    assert conn.algorithm_selection is not None

    signature = conn.host_key.sign_encode(
      conn.algorithm_selection.server_host_key_algorithm,
      exchange_hash,
    )

    reply_message = KexEcdhReplyMessage(
      k_s=encoded_host_public_key,
      q_s=server_public_key_string,
      signature=signature,
    )

    conn.write_message(reply_message)

    return exchange_hash, shared_key
