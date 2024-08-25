import hashlib
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import dh

from ..messages.kex_dh_gex import (KexDhGexGroupMessage, KexDhGexInitMessage,
                                   KexDhGexReplyMessage,
                                   KexDhGexRequestMessage)
from ..prime import find_prime
from ..structures.primitives import encode_mpint, encode_string
from .base import KeyExchange


# See: RFC 4419

@dataclass(slots=True)
class DhKeyExchange(KeyExchange):
  def hash(self, data: bytes, /) -> bytes:
    return hashlib.sha256(data).digest()

  async def run(
    self,
    conn,
    read,
    client_kex_init_payload,
    server_kex_init_payload
  ):
    # Receive KexDhGexRequest message

    kex_dh_gex_request, _ = await read(KexDhGexRequestMessage)

    # TODO: Checks on min, n, max

    prime = find_prime(conn.server.primes, kex_dh_gex_request.min, kex_dh_gex_request.n, kex_dh_gex_request.max)

    if prime:
      param_numbers = dh.DHParameterNumbers(p=prime.value, g=prime.generator)
    else:
      param_numbers = dh.generate_parameters(generator=2, key_size=kex_dh_gex_request.n).parameter_numbers()


    # Receive KexDhGexGroup message

    conn.write_message(KexDhGexGroupMessage(p=param_numbers.p, g=param_numbers.g))

    kex_dh_init, _ = await read(KexDhGexInitMessage)


    server_private_key = param_numbers.parameters().generate_private_key()
    server_public_key = server_private_key.public_key()
    server_f = server_public_key.public_numbers().y

    client_public_key = dh.DHPublicNumbers(kex_dh_init.e, param_numbers).public_key()

    shared_key = server_private_key.exchange(client_public_key)


    # Send KexDhGexReply message

    assert conn.host_key is not None

    encoded_host_public_key = conn.host_key.encode_public_key()
    encoded_shared_secret = encode_mpint(int.from_bytes(shared_key))

    assert conn.client_ident_string is not None
    assert conn.server_ident_string is not None

    data_to_hash =\
        encode_string(bytes(conn.client_ident_string))\
      + encode_string(bytes(conn.server_ident_string))\
      + encode_string(client_kex_init_payload)\
      + encode_string(server_kex_init_payload)\
      + encode_string(encoded_host_public_key)\
      + struct.pack('>III', kex_dh_gex_request.min, kex_dh_gex_request.n, kex_dh_gex_request.max)\
      + encode_mpint(param_numbers.p)\
      + encode_mpint(param_numbers.g)\
      + encode_mpint(kex_dh_init.e)\
      + encode_mpint(server_f)\
      + encoded_shared_secret

    assert conn.algorithm_selection is not None

    exchange_hash = self.hash(data_to_hash)
    signature = conn.host_key.sign_encode(conn.algorithm_selection.server_host_key_algorithm, exchange_hash)

    kex_dh_gex_reply = KexDhGexReplyMessage(
      host_key=encoded_host_public_key,
      f=server_f,
      signature=signature
    )

    conn.write_message(kex_dh_gex_reply)


    return exchange_hash, shared_key
