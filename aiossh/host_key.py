from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal, cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (ec, ed25519, padding,
                                                       rsa, utils)
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .structures.keys import (ECDSAIdentifier, encode_ecdsa_public_key,
                              encode_ecdsa_signature,
                              encode_ed25519_public_key,
                              encode_ed25519_signature, encode_rsa_public_key)
from .structures.primitives import encode_name, encode_string


class HostKey[T](ABC):
  def algorithms(self) -> frozenset[T]:
    ...

  @abstractmethod
  def encode_public_key(self) -> bytes:
    ...

  @abstractmethod
  def sign_encode(self, algorithm: T, data: bytes) -> bytes:
    ...


## ED25519

type ED25519HostKeyAlgorithmName = Literal['ssh-ed25519']

@dataclass(slots=True)
class ED25519HostKey(HostKey[ED25519HostKeyAlgorithmName]):
  # algorithms: frozenset[ED25519HostKeyAlgorithmName] = field(default=frozenset({'ssh-ed25519'}), init=False)
  private_key: ed25519.Ed25519PrivateKey

  def algorithms(self):
    return frozenset[ED25519HostKeyAlgorithmName]({'ssh-ed25519'})

  def encode_public_key(self):
    return encode_ed25519_public_key(self.private_key.public_key())

  def sign_encode(self, algorithm, data):
    return encode_ed25519_signature(self.private_key.sign(data))

  def __getstate__(self):
    return self.private_key.private_bytes_raw()

  def __setstate__(self, state: bytes):
    # self.algorithms = frozenset({'ssh-ed25519'})
    self.private_key = ed25519.Ed25519PrivateKey.from_private_bytes(state)


## ECDSA

# See: RFC 5656 Section 6.2.1

type ECDSAHostKeyAlgorithmName = Literal['ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521']

@dataclass(slots=True)
class ECDSAHostKey(HostKey[ECDSAHostKeyAlgorithmName]):
  private_key: ec.EllipticCurvePrivateKey

  def algorithms(self):
    return frozenset[ECDSAHostKeyAlgorithmName]({cast(ECDSAHostKeyAlgorithmName, f'ecdsa-sha2-{self.identifier}')})

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

  def sign_encode(self, algorithm, data):
    curve_size = self.private_key.curve.key_size

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


## RSA

# See: RFC 4253 Section 6.6
# See: RFC 8332

type RSAHostKeyAlgorithmName = Literal['ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512']

@dataclass(slots=True)
class RSAHostKey(HostKey[RSAHostKeyAlgorithmName]):
  private_key: rsa.RSAPrivateKey
  supported_algorithms: frozenset[RSAHostKeyAlgorithmName]

  def algorithms(self):
    return self.supported_algorithms

  def encode_public_key(self):
    return encode_rsa_public_key(self.private_key.public_key())

  def sign_encode(self, algorithm, data):
    match algorithm:
      case 'ssh-rsa':
        hash = hashes.SHA1()
      case 'rsa-sha2-256':
        hash = hashes.SHA256()
      case 'rsa-sha2-512':
        hash = hashes.SHA512()

    signed = self.private_key.sign(data, padding.PKCS1v15(), hash)

    return encode_name(algorithm) + encode_string(signed)

  def __getstate__(self):
    return self.supported_algorithms, self.private_key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.PKCS8,
      encryption_algorithm=serialization.NoEncryption()
    )

  def __setstate__(self, state: tuple):
    self.supported_algorithms = state[0]
    self.private_key = load_pem_private_key(state[1], password=None) # type: ignore
