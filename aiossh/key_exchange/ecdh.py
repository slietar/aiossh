from dataclasses import dataclass
from typing import ClassVar, override

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    SECP256R1,
    SECP384R1,
    SECP521R1,
    EllipticCurvePublicKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.hashes import Hash
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from ..encoding import Codable
from ..error import ProtocolError
from ..messages.base import Message
from ..public.ecdsa import ECDSAIdentifier, get_hash_from_curve_size
from ..structures.primitives import encode_mpint, encode_string
from .base import KeyExchange


# See: RFC 5656 Section 4

@dataclass(kw_only=True, slots=True)
class KexEcdhInitMessage(Codable, Message):
    id: ClassVar[int] = 30

    q_h: bytes

@dataclass(kw_only=True, slots=True)
class KexEcdhReplyMessage(Codable, Message):
    id: ClassVar[int] = 31

    k_s: bytes
    q_s: bytes
    signature: bytes


def get_curve_from_identifier(identifier: ECDSAIdentifier):
  match identifier:
    case 'nistp256':
      return SECP256R1()
    case 'nistp384':
      return SECP384R1()
    case 'nistp521':
      return SECP521R1()
    case _:
      raise ValueError('Unsupported identifier')


@dataclass(slots=True)
class EcdhKeyExchange(KeyExchange):
  identifier: ECDSAIdentifier

  @property
  def curve(self):
    return get_curve_from_identifier(self.identifier)

  @override
  def hash(self, data: bytes, /):
    digest = Hash(
      get_hash_from_curve_size(self.curve.key_size),
    )

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
      client_public_key = EllipticCurvePublicKey.from_encoded_point(self.curve, init_message.q_h)
    except ValueError as e:
      raise ProtocolError from e

    private_key = generate_private_key(self.curve)

    server_public_key_string = private_key.public_key().public_bytes(
      encoding=Encoding.X962,
      format=PublicFormat.UncompressedPoint,
    )

    shared_key = private_key.exchange(
      ECDH(),
      client_public_key,
    )

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
