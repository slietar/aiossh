from dataclasses import dataclass
from typing import override

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

from ..error import ProtocolError
from ..flow import MessageFlow
from ..messages.key_exchange import KexEcdhInitMessage, KexEcdhReplyMessage
from ..public.ecdsa import ECDSAIdentifier, get_hash_from_curve_size
from ..structures.primitives import encode_mpint, encode_string
from .base import KeyExchange


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
  def run_as_server(
    self,
    conn,
    algorithm_selection,
    host_key,
    hash_header,
  ) -> MessageFlow[tuple[bytes, bytes]]:
    kex_ecdh_init = (yield).decode(KexEcdhInitMessage)

    try:
      client_public_key = EllipticCurvePublicKey.from_encoded_point(self.curve, kex_ecdh_init.q_h)
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
