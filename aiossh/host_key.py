from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .structures.keys import (ECDSAIdentifier, encode_ecdsa_public_key,
                              encode_ed25519_public_key)


class HostKey(ABC):
  @abstractmethod
  def algorithm(self) -> str:
    ...

  @abstractmethod
  def encode_public_key(self) -> bytes:
    ...


@dataclass(slots=True)
class ED25519HostKey(HostKey):
  private_key: ed25519.Ed25519PrivateKey

  def algorithm(self):
    return 'ssh-ed25519'

  def encode_public_key(self):
    return encode_ed25519_public_key(self.private_key.public_key())

  def __getstate__(self):
    return self.private_key.private_bytes_raw()

  def __setstate__(self, state: bytes):
    self.private_key = ed25519.Ed25519PrivateKey.from_private_bytes(state)


@dataclass(slots=True)
class ECDSAHostKey(HostKey):
  private_key: ec.EllipticCurvePrivateKey

  def algorithm(self):
    return f'ecdsa-sha2-{self.identifier}'

  @property
  def identifier(self):
    return cast(ECDSAIdentifier, {
      'secp256r1': 'nistp256',
      'secp384r1': 'nistp384',
      'secp521r1': 'nistp521'
    }[self.private_key.curve.name])

  def encode_public_key(self):
    return encode_ecdsa_public_key(self.private_key.public_key(), self.identifier)

  def __getstate__(self):
    return self.private_key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.PKCS8,
      encryption_algorithm=serialization.NoEncryption()
    )

  def __setstate__(self, state: bytes):
    self.private_key = load_pem_private_key(state, password=None) # type: ignore
