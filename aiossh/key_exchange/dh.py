import hashlib
import struct
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import dh

from ..messages.kex_dh_gex import (KexDhGexGroupMessage, KexDhGexInitMessage,
                                   KexDhGexReplyMessage,
                                   KexDhGexRequestMessage)
from ..messages.kex_init import KexInitMessage
from ..prime import find_prime
from ..structures.primitives import encode_mpint

if TYPE_CHECKING:
  from ..connection import Connection


async def run_kex_dh(
  conn: 'Connection',
  client_ident_string: bytes,
  server_ident_string: bytes,
  client_kex_init: KexInitMessage,
  server_kex_init: KexInitMessage
):
  # Run key exchange

  kex_dh_gex_request = await conn.read_message()
  assert isinstance(kex_dh_gex_request, KexDhGexRequestMessage)

  # TODO: Checks on min, n, max

  prime = find_prime(conn.server.primes, kex_dh_gex_request.min, kex_dh_gex_request.n, kex_dh_gex_request.max)

  if prime:
    param_numbers = dh.DHParameterNumbers(p=prime.value, g=prime.generator)
  else:
    param_numbers = dh.generate_parameters(generator=2, key_size=kex_dh_gex_request.n).parameter_numbers()


  conn.write_message(KexDhGexGroupMessage(p=param_numbers.p, g=param_numbers.g))

  kex_dh_init = await conn.read_message()
  assert isinstance(kex_dh_init, KexDhGexInitMessage)


  server_private_key = param_numbers.parameters().generate_private_key()
  server_public_key = server_private_key.public_key()
  server_f = server_public_key.public_numbers().y

  client_public_key = dh.DHPublicNumbers(kex_dh_init.e, param_numbers).public_key()

  shared_key = server_private_key.exchange(client_public_key)

  assert conn.algorithm_selection is not None
  host_key = next(key for key in conn.server.host_keys if key.algorithm == conn.algorithm_selection.server_host_key_algorithm)

  encoded_host_public_key = host_key.encode_public_key()


  signed_data =\
      client_ident_string\
    + server_ident_string\
    + client_kex_init.encode_payload()\
    + server_kex_init.encode_payload()\
    + encoded_host_public_key\
    + struct.pack('>III', kex_dh_gex_request.min, kex_dh_gex_request.n, kex_dh_gex_request.max)\
    + encode_mpint(param_numbers.p)\
    + encode_mpint(param_numbers.g)\
    + encode_mpint(kex_dh_init.e)\
    + encode_mpint(server_f)\
    + shared_key

  # print(xx.hex(' '))

  kex_dh_gex_reply = KexDhGexReplyMessage(
    host_key=encoded_host_public_key,
    f=server_f,
    signature=hashlib.sha256(signed_data).digest()
  )

  conn.write_message(kex_dh_gex_reply)
