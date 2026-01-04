from dataclasses import dataclass
from typing import Literal, override

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
  Ed25519PrivateKey as CryptographyEd25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
  Ed25519PublicKey as CryptographyED25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
  Encoding,
  PublicFormat,
)

from ..error import ProtocolError
from ..structures.primitives import (
  decode_name,
  decode_string,
  encode_name,
  encode_string,
)
from ..util import ReadableBytesIO, ReadableBytesIOImpl
from .base import PrivateKey, PublicKey


# See: RFC 8709


type ED25519SignatureAlgorithmName = Literal['ssh-ed25519']


@dataclass(slots=True)
class ED25519PublicKey(PublicKey[ED25519SignatureAlgorithmName]):
  key: CryptographyED25519PublicKey

  @override
  def encode(self):
    return encode_name('ssh-ed25519') + encode_string(self.key.public_bytes(
      encoding=Encoding.Raw,
      format=PublicFormat.Raw,
    ))

  @override
  def decode_verify(self, algorithm: ED25519SignatureAlgorithmName, encoded_signature: bytes, data: bytes):
    with ReadableBytesIOImpl(encoded_signature) as reader:
      if decode_name(reader) != 'ssh-ed25519':
        raise ProtocolError

      signature = decode_string(reader)

    try:
      self.key.verify(signature, data)
    except InvalidSignature:
      return False
    else:
      return True

  @override
  @classmethod
  def decode(cls, reader: ReadableBytesIO):
    if decode_name(reader) != 'ssh-ed25519':
      raise ProtocolError

    return cls(
      CryptographyED25519PublicKey.from_public_bytes(
        decode_string(reader, size=32),
      ),
    )


@dataclass(slots=True)
class ED25519PrivateKey(PrivateKey[ED25519SignatureAlgorithmName]):
  key: CryptographyEd25519PrivateKey

  @override
  def algorithms(self):
    return frozenset({
      'ssh-ed25519',
    })

  @override
  def sign_encode(self, algorithm: ED25519SignatureAlgorithmName, data: bytes):
    assert algorithm == 'ssh-ed25519'

    return encode_name('ssh-ed25519') + encode_string(
      self.key.sign(data),
    )

  @override
  def to_public_key(self):
    return ED25519PublicKey(
      self.key.public_key(),
    )

  @override
  def __getstate__(self):
    return self.key.private_bytes_raw()

  def __setstate__(self, state: bytes):
    self.key = CryptographyEd25519PrivateKey.from_private_bytes(state)

  @classmethod
  def generate(cls):
    return cls(
      CryptographyEd25519PrivateKey.generate(),
    )
