from typing import Literal
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from .primitives import encode_mpint, encode_string


# See: RFC 5656 Section 3.1

ECDSAIdentifier = Literal['nistp256', 'nistp384', 'nistp521']

def encode_ecdsa_public_key(key: ec.EllipticCurvePublicKey, /, identifier: ECDSAIdentifier):
  return encode_string(b'ecdsa-sha2-' + identifier.encode()) + encode_string(identifier.encode()) + encode_string(key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
  ))


# See: RFC 8709 Section 4

def encode_ed25519_public_key(key: ed25519.Ed25519PublicKey, /):
  return encode_string(b'ssh-ed25519') + encode_string(key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
  ))


# See: RFC 4256 Section 6.6

def encode_rsa_public_key(key: rsa.RSAPublicKey, /):
  numbers = key.public_numbers()
  return encode_string(b'ssh-rsa') + encode_mpint(numbers.e) + encode_mpint(numbers.n)
