import struct
from abc import ABC, abstractmethod
from collections.abc import Generator
from dataclasses import dataclass
from typing import override

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.poly1305 import Poly1305

from .encryption.base import Encryption
from .error import IntegrityVerificationError, ProtocolError
from .integrity.base import IntegrityVerification
from .packet import encode_packet
from .structures.primitives import encode_uint64
from .utilities import GeneratorWrapper


PACKET_LENGTH_SIZE = 4
PADDING_LENGTH_SIZE = 1

type HandlerGenerator = Generator[int, bytes, bytes]


@dataclass(slots=True)
class HandlerState:
  generator: GeneratorWrapper[int, bytes, bytes]
  requested_size: int

class Handler(ABC):
  @abstractmethod
  def receive(self, sequence_number: int) -> HandlerGenerator:
    ...

  @abstractmethod
  def send(self, sequence_number: int, payload: bytes) -> bytes:
    ...


class ChaCha20Poly1305Handler(Handler):
  _length_key: bytes
  _payload_key: bytes

  def __init__(self, key: bytes):
    assert len(key) == 64

    self._payload_key = key[0:32]
    self._length_key = key[32:64]

  def _nonce(self, counter: int, sequence_number: int, /):
    # cryptography's ChaCha20(key, nonce) nonce argument is 16 bytes:
    # 4-byte little-endian initial block counter || 12-byte nonce. The
    # 12-byte nonce here is 4 zero bytes || 8-byte big-endian sequence
    # number, matching OpenSSH's wire format.
    return counter.to_bytes(4, 'little') + b'\x00\x00\x00\x00' + encode_uint64(sequence_number)

  @override
  def receive(self, sequence_number: int):
    encrypted_length = yield PACKET_LENGTH_SIZE

    length_cipher = Cipher(
      ChaCha20(self._length_key, self._nonce(0, sequence_number)),
      mode=None,
    )

    length_bytes = length_cipher.decryptor().update(encrypted_length)
    length = struct.unpack('>I', length_bytes)[0]

    tag_size = 16
    encrypted_packet_with_tag = yield length + tag_size

    tag = encrypted_packet_with_tag[-tag_size:]
    encrypted_packet = encrypted_packet_with_tag[:-tag_size]

    tag_cipher = Cipher(
      ChaCha20(self._payload_key, self._nonce(0, sequence_number)),
      mode=None,
    )

    tag_key = tag_cipher.encryptor().update(b'\x00' * 32)

    try:
      Poly1305.verify_tag(tag_key, encrypted_length + encrypted_packet, tag)
    except InvalidSignature as e:
      raise IntegrityVerificationError from e

    payload_cipher = Cipher(
      ChaCha20(self._payload_key, self._nonce(1, sequence_number)),
      mode=None,
    )

    return payload_cipher.decryptor().update(encrypted_packet)

  @override
  def send(self, sequence_number: int, payload: bytes):
    packet_with_length = encode_packet(payload, block_size=8, length_field_size=0)

    raw_length = packet_with_length[:PACKET_LENGTH_SIZE]
    raw_packet = packet_with_length[PACKET_LENGTH_SIZE:]

    length_cipher = Cipher(
      ChaCha20(self._length_key, self._nonce(0, sequence_number)),
      mode=None,
    )

    encrypted_length = length_cipher.encryptor().update(raw_length)

    payload_cipher = Cipher(
      ChaCha20(self._payload_key, self._nonce(1, sequence_number)),
      mode=None,
    )

    encrypted_packet = payload_cipher.encryptor().update(raw_packet)

    tag_cipher = Cipher(
      ChaCha20(self._payload_key, self._nonce(0, sequence_number)),
      mode=None,
    )

    tag_key = tag_cipher.encryptor().update(b'\x00' * 32)
    tag = Poly1305.generate_tag(tag_key, encrypted_length + encrypted_packet)

    return encrypted_length + encrypted_packet + tag


class NoneHandler(Handler):
  @override
  def receive(self, sequence_number: int):
    length_bytes = yield PACKET_LENGTH_SIZE
    length = struct.unpack('>I', length_bytes)[0]

    if length < PADDING_LENGTH_SIZE:
      raise ProtocolError

    packet = yield length

    return packet

  @override
  def send(self, sequence_number: int, payload: bytes):
    return encode_packet(payload)


@dataclass(slots=True)
class DefaultHandler(Handler):
  encryption: Encryption
  integrity_verification: IntegrityVerification

  @override
  def receive(self, sequence_number: int):
    # Head = first block
    # Body = without first block
    encrypted_head = yield self.encryption.block_size()
    head = self.encryption.decrypt_blocks(encrypted_head)

    length_bytes = head[:PACKET_LENGTH_SIZE]
    length = struct.unpack('>I', length_bytes)[0]

    if (PACKET_LENGTH_SIZE + length) % max(self.encryption.block_size(), 8) != 0:
      raise ProtocolError

    if length < PADDING_LENGTH_SIZE:
      raise ProtocolError

    encrypted_body_and_digest = yield PACKET_LENGTH_SIZE + length + self.integrity_verification.digest_size - self.encryption.block_size()

    encrypted_body = encrypted_body_and_digest[:-self.integrity_verification.digest_size]
    body = self.encryption.decrypt_blocks(encrypted_body)
    digest = encrypted_body_and_digest[-self.integrity_verification.digest_size:]

    length_and_packet = head + body
    packet = length_and_packet[PACKET_LENGTH_SIZE:]

    self.integrity_verification.start(sequence_number)
    self.integrity_verification.update(length_and_packet)
    reference_digest = self.integrity_verification.digest()

    if not bytes_eq(digest, reference_digest):
      raise IntegrityVerificationError

    return packet

  @override
  def send(self, sequence_number: int, payload: bytes):
    length_and_packet = encode_packet(payload, block_size=self.encryption.block_size())
    encrypted_length_and_packet = self.encryption.encrypt_blocks(length_and_packet)

    self.integrity_verification.start(sequence_number)
    self.integrity_verification.update(length_and_packet)

    digest = self.integrity_verification.digest()

    return encrypted_length_and_packet + digest
