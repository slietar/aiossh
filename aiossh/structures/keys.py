from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from ..error import ProtocolError
from ..util import ReadableBytesIO
from .primitives import (decode_name, decode_string, encode_mpint, encode_name,
                         encode_string)


## ECDSA

type ECDSAIdentifier = Literal['nistp256', 'nistp384', 'nistp521']

def encode_ecdsa_public_key(key: ec.EllipticCurvePublicKey, /, identifier: ECDSAIdentifier):
  # See: RFC 5656 Section 3.1

  return encode_name(f'ecdsa-sha2-{identifier}') + encode_string(identifier.encode()) + encode_string(key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
  ))

def encode_ecdsa_signature(r: int, s: int, /, identifier: ECDSAIdentifier):
  # See: RFC 5656 Section 3.1.2

  return encode_name(f'ecdsa-sha2-{identifier}') + encode_string(
    encode_mpint(r) + encode_mpint(s)
  )


## ED25519

# See: RFC 8709 Section 4

def encode_ed25519_public_key(key: ed25519.Ed25519PublicKey, /):
  return encode_name('ssh-ed25519') + encode_string(key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
  ))

def decode_ed25519_public_key(reader: ReadableBytesIO):
  if decode_name(reader) != 'ssh-ed25519':
    raise ProtocolError

  return ed25519.Ed25519PublicKey.from_public_bytes(decode_string(reader))


# See: RFC 8709 Section 6

def encode_ed25519_signature(signature: bytes, /):
  return encode_name('ssh-ed25519') + encode_string(signature)

def decode_ed25519_signature(reader: ReadableBytesIO):
  if decode_name(reader) != 'ssh-ed25519':
    raise ProtocolError

  return decode_string(reader)


## RSA

def encode_rsa_public_key(key: rsa.RSAPublicKey, /):
  # See: RFC 4256 Section 6.6

  numbers = key.public_numbers()
  return encode_name('ssh-rsa') + encode_mpint(numbers.e) + encode_mpint(numbers.n)
