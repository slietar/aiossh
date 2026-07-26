import math
import os
import struct
from typing import Optional


MIN_PADDING = 4

def encode_packet(payload: bytes, *, block_size: Optional[int] = None, length_field_size: int = 4):
  # AEAD ciphers (length_field_size=0) encrypt the 4-byte length field
  # separately and exclude it from the block-alignment target, unlike the
  # base RFC 4253 scheme which includes it.

  actual_block_size = block_size or 8
  padding_length = 0

  len_base = len(payload) + 1 + length_field_size
  len_min_padded = len_base + MIN_PADDING
  len_padded = math.ceil(len_min_padded / actual_block_size) * actual_block_size

  padding_length = len_padded - len_min_padded + MIN_PADDING

  assert (len_base + padding_length) % actual_block_size == 0
  assert MIN_PADDING <= padding_length <= 0xff

  packet = struct.pack('>B', padding_length) + payload + os.urandom(padding_length)
  return struct.pack('>I', len(packet)) + packet

  # print(f'{len_min_padded=}')
  # print(f'{len_padded=}')
  # print(f'{padding_length=}')
  # print(len(payload) + 5 + padding_length)

# print(encode_packet(b'foo').hex(' '))
