from dataclasses import dataclass
from typing import override

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.poly1305 import Poly1305

from ..structures.primitives import encode_uint64
from .base import AEADEncryption


# See: draft-ietf-sshm-chacha20-poly1305-01
#
# 64 bytes of key material split into two independent ChaCha20 keys:
# key_payload (first 32 bytes) encrypts the payload and derives the
# per-packet Poly1305 key; key_length (last 32 bytes) encrypts only the
# 4-byte packet length field. This matches OpenSSH's cipher-chachapoly.c
# (main_key = key[0:32], header_key = key[32:64]).

@dataclass(slots=True)
class ChaCha20Poly1305Encryption(AEADEncryption):
  _payload_key: bytes
  _length_key: bytes

  @override
  def __init__(self, key: bytes):
    assert len(key) == self.key_size()

    self._payload_key = key[0:32]
    self._length_key = key[32:64]

  @staticmethod
  def _nonce(counter: int, sequence_number: int, /):
    # cryptography's ChaCha20(key, nonce) nonce argument is 16 bytes:
    # 4-byte little-endian initial block counter || 12-byte nonce. The
    # 12-byte nonce here is 4 zero bytes || 8-byte big-endian sequence
    # number, matching OpenSSH's wire format.
    return counter.to_bytes(4, 'little') + b'\x00\x00\x00\x00' + encode_uint64(sequence_number)

  def _poly1305_key(self, sequence_number: int, /):
    cipher = Cipher(ChaCha20(self._payload_key, self._nonce(0, sequence_number)), mode=None)
    return cipher.encryptor().update(b'\x00' * 32)

  @override
  def decrypt_length(self, sequence_number: int, encrypted_length: bytes, /):
    assert len(encrypted_length) == 4

    cipher = Cipher(ChaCha20(self._length_key, self._nonce(0, sequence_number)), mode=None)
    return cipher.decryptor().update(encrypted_length)

  @override
  def decrypt_and_verify_packet(self, sequence_number: int, encrypted_length: bytes, encrypted_rest: bytes, tag: bytes, /):
    poly_key = self._poly1305_key(sequence_number)
    Poly1305.verify_tag(poly_key, encrypted_length + encrypted_rest, tag)

    cipher = Cipher(ChaCha20(self._payload_key, self._nonce(1, sequence_number)), mode=None)
    return cipher.decryptor().update(encrypted_rest)

  @override
  def encrypt_packet(self, sequence_number: int, packet_with_length: bytes, /):
    raw_length = packet_with_length[:4]
    raw_rest = packet_with_length[4:]

    length_cipher = Cipher(ChaCha20(self._length_key, self._nonce(0, sequence_number)), mode=None)
    encrypted_length = length_cipher.encryptor().update(raw_length)

    rest_cipher = Cipher(ChaCha20(self._payload_key, self._nonce(1, sequence_number)), mode=None)
    encrypted_rest = rest_cipher.encryptor().update(raw_rest)

    poly_key = self._poly1305_key(sequence_number)
    tag = Poly1305.generate_tag(poly_key, encrypted_length + encrypted_rest)

    return encrypted_length + encrypted_rest + tag

  @override
  @staticmethod
  def block_size():
    return 8

  @override
  @staticmethod
  def key_size():
    return 64

  @override
  @staticmethod
  def tag_size():
    return 16
