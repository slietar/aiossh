from dataclasses import dataclass
from typing import Literal, override

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import (
  RSAPrivateKey as CryptographyRSAPrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
  RSAPublicKey as CryptographyRSAPublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
  RSAPublicNumbers,
  generate_private_key,
)
from cryptography.hazmat.primitives.hashes import SHA1, SHA256, SHA512
from cryptography.hazmat.primitives.serialization import (
  Encoding,
  NoEncryption,
  PrivateFormat,
  load_pem_private_key,
)

from ..error import ProtocolError, UnreachableError
from ..structures.primitives import (
  decode_mpint,
  decode_name,
  decode_string,
  encode_mpint,
  encode_name,
  encode_string,
)
from ..util import ReadableBytesIO, ReadableBytesIOImpl
from .base import PrivateKey, PublicKey


# See: RFC 4253 Section 6.6
# See: RFC 8332


type RSASignatureAlgorithmName = Literal['ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512']


def get_hash(algorithm: RSASignatureAlgorithmName):
  match algorithm:
    case 'ssh-rsa':
      return SHA1()
    case 'rsa-sha2-256':
      return SHA256()
    case 'rsa-sha2-512':
      return SHA512()
    case _:
      raise UnreachableError


@dataclass(slots=True)
class RSAPublicKey(PublicKey[RSASignatureAlgorithmName]):
  key: CryptographyRSAPublicKey

  @override
  def encode(self):
    numbers = self.key.public_numbers()
    return encode_name('ssh-rsa') + encode_mpint(numbers.e) + encode_mpint(numbers.n)

  @override
  def decode_verify(self, algorithm: RSASignatureAlgorithmName, encoded_signature: bytes, data: bytes):
    with ReadableBytesIOImpl(encoded_signature) as reader:
      if decode_name(reader) != algorithm:
        raise ProtocolError

      signature = decode_string(reader)

    try:
      self.key.verify(
        signature,
        data,
        padding=PKCS1v15(),
        algorithm=get_hash(algorithm),
      )
    except InvalidSignature:
      return False
    else:
      return True

  @classmethod
  @override
  def decode(cls, reader: ReadableBytesIO):
    if decode_name(reader) != 'ssh-rsa':
      raise ProtocolError

    e = decode_mpint(reader)
    n = decode_mpint(reader)

    return cls(
      RSAPublicNumbers(e=e, n=n).public_key(),
    )


@dataclass(slots=True)
class RSAPrivateKey(PrivateKey[RSASignatureAlgorithmName]):
  key: CryptographyRSAPrivateKey

  @override
  def algorithms(self):
    return frozenset({
      'ssh-rsa',
      'rsa-sha2-256',
      'rsa-sha2-512',
    })

  @override
  def sign_encode(self, algorithm: RSASignatureAlgorithmName, data: bytes):
    signed = self.key.sign(
      data,
      padding=PKCS1v15(),
      algorithm=get_hash(algorithm),
    )

    return encode_name(algorithm) + encode_string(signed)

  @override
  def to_public_key(self):
    return RSAPublicKey(
      self.key.public_key(),
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
    return cls(
      generate_private_key(public_exponent=65537, key_size=2048),
    )
