from dataclasses import dataclass
from typing import Literal, override

from cryptography.hazmat.primitives.asymmetric.ec import (
  ECDSA,
  SECP256R1,
  EllipticCurvePrivateKey,
  EllipticCurvePublicKey,
  generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.serialization import (
  Encoding,
  NoEncryption,
  PrivateFormat,
  PublicFormat,
  load_pem_private_key,
)

from ..structures.primitives import (
  encode_mpint,
  encode_name,
  encode_string,
)
from ..util import ReadableBytesIO
from .base import PrivateKey, PublicKey


# See: RFC 5656 Section 6.2.1


type ECDSASignatureAlgorithmName = Literal['ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521']
type ECDSAIdentifier = Literal['nistp256', 'nistp384', 'nistp521']


def get_identifier_from_key(key: EllipticCurvePublicKey | EllipticCurvePrivateKey):
  match key.curve.name:
    case 'secp256r1':
      return 'nistp256'
    case 'secp384r1':
      return 'nistp384'
    case 'secp521r1':
      return 'nistp521'
    case _:
      raise ValueError('Unsupported curve')

def get_hash_from_curve_size(curve_size: int):
  if curve_size <= 256:
    return SHA256()
  elif curve_size <= 384:
    return SHA384()
  else:
    return SHA512()


@dataclass(slots=True)
class ECDSAPublicKey(PublicKey[ECDSASignatureAlgorithmName]):
  key: EllipticCurvePublicKey

  @property
  def identifier(self):
    return get_identifier_from_key(self.key)

  @override
  def encode(self):
    # See: RFC 5656 Section 3.1

    return encode_name(f'ecdsa-sha2-{self.identifier}') + encode_string(self.identifier.encode()) + encode_string(
      self.key.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint,
      ),
    )

  @override
  def decode_verify(self, algorithm: ECDSASignatureAlgorithmName, encoded_signature: bytes, data: bytes) -> bool:
    raise NotImplementedError

  @classmethod
  @override
  def decode(cls, reader: ReadableBytesIO):
    raise NotImplementedError



@dataclass(slots=True)
class ECDSAPrivateKey(PrivateKey[ECDSASignatureAlgorithmName]):
  key: EllipticCurvePrivateKey

  @property
  def identifier(self):
    return get_identifier_from_key(self.key)

  @override
  def algorithms(self):
    return frozenset({
      f'ecdsa-sha2-{self.identifier}',
    })

  @override
  def to_public_key(self):
    return ECDSAPublicKey(
      self.key.public_key(),
    )

  @override
  def sign_encode(self, algorithm: ECDSASignatureAlgorithmName, data: bytes):
    # See: RFC 5656 Section 3.1.2

    der_signature = self.key.sign(
      data,
      signature_algorithm=ECDSA(
        get_hash_from_curve_size(self.key.curve.key_size),
      ),
    )

    r, s = decode_dss_signature(der_signature)

    return encode_name(f'ecdsa-sha2-{self.identifier}') + encode_string(
      encode_mpint(r) + encode_mpint(s),
    )

  @override
  def __getstate__(self):
    return self.key.private_bytes(
      encoding=Encoding.PEM,
      format=PrivateFormat.PKCS8,
      encryption_algorithm=NoEncryption(),
    )

  def __setstate__(self, state: bytes):
    self.key = load_pem_private_key(state, password=None) # type: ignore

  @classmethod
  def generate(cls):
    return cls(generate_private_key(SECP256R1()))
