from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .structures.keys import (ECDSAIdentifier, encode_ecdsa_public_key,
                              encode_ecdsa_signature,
                              encode_ed25519_public_key,
                              encode_ed25519_signature)


class HostKey(ABC):
  @abstractmethod
  def algorithm(self) -> str:
    ...

  @abstractmethod
  def encode_public_key(self) -> bytes:
    ...

  @abstractmethod
  def sign_encode(self, data: bytes, /) -> bytes:
    ...


@dataclass(slots=True)
class ED25519HostKey(HostKey):
  private_key: ed25519.Ed25519PrivateKey

  def algorithm(self):
    return 'ssh-ed25519'

  def encode_public_key(self):
    return encode_ed25519_public_key(self.private_key.public_key())

  def sign_encode(self, data: bytes, /):
    return encode_ed25519_signature(self.private_key.sign(data))

  def __getstate__(self):
    return self.private_key.private_bytes_raw()

  def __setstate__(self, state: bytes):
    self.private_key = ed25519.Ed25519PrivateKey.from_private_bytes(state)


@dataclass(slots=True)
class ECDSAHostKey(HostKey):
  private_key: ec.EllipticCurvePrivateKey

  @property
  def identifier(self):
    return cast(ECDSAIdentifier, {
      'secp256r1': 'nistp256',
      'secp384r1': 'nistp384',
      'secp521r1': 'nistp521'
    }[self.private_key.curve.name])

  def algorithm(self):
    return f'ecdsa-sha2-{self.identifier}'

  def encode_public_key(self):
    return encode_ecdsa_public_key(self.private_key.public_key(), self.identifier)

  def sign_encode(self, data: bytes, /):
    # See: RFC 5656 Section 6.2.1

    curve_size = self.private_key.curve.key_size
    print('>', curve_size)

    if curve_size <= 256:
      hash_algorithm = hashes.SHA256()
    elif curve_size <= 384:
      hash_algorithm = hashes.SHA384()
    else:
      hash_algorithm = hashes.SHA512()

    der_signature = self.private_key.sign(data, signature_algorithm=ec.ECDSA(hash_algorithm))
    r, s = utils.decode_dss_signature(der_signature)

    return encode_ecdsa_signature(r, s, self.identifier)

  def __getstate__(self):
    return self.private_key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.PKCS8,
      encryption_algorithm=serialization.NoEncryption()
    )

  def __setstate__(self, state: bytes):
    self.private_key = load_pem_private_key(state, password=None) # type: ignore
