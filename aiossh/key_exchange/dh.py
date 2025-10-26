import hashlib
import logging
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import dh

from ..error import ProtocolError
from ..messages.kex_dh_gex import (
  KexDhGexGroupMessage,
  KexDhGexInitMessage,
  KexDhGexReplyMessage,
  KexDhGexRequestMessage,
)
from ..primes.group import select_group
from ..structures.primitives import encode_mpint, encode_string
from .base import KeyExchange


logger = logging.getLogger(__name__)


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
    server_kex_init_payload,
  ):
    # Receive KexDhGexRequest message

    kex_dh_gex_request, _ = await read(KexDhGexRequestMessage)

    if not (
      (kex_dh_gex_request.min <= kex_dh_gex_request.n <= kex_dh_gex_request.max)
      and (kex_dh_gex_request.max >= 1024)
    ):
      raise ProtocolError

    # The p and g parameter numbers can be reused.
    # See: https://crypto.stackexchange.com/a/2019

    # It is important to use the well-known groups because OpenSSL, which is used as cryptography's backend, knows them and can skip checks.
    # See: https://github.com/openssl/openssl/blob/311f7bd6dd609cd32faa406bbddca580ae4fd4eb/crypto/dh/dh_group_params.c#L56

    group = select_group(conn.server.dh_groups, min(kex_dh_gex_request.min, 1024), kex_dh_gex_request.n, kex_dh_gex_request.max)

    if group is None:
      raise ProtocolError

    param_numbers = dh.DHParameterNumbers(p=group.prime, g=group.generator)

    logger.debug(f'Selected group with {group.size} bits')


    # Receive KexDhGexGroup message

    conn.write_message(KexDhGexGroupMessage(p=param_numbers.p, g=param_numbers.g))

    kex_dh_init, _ = await read(KexDhGexInitMessage)

    server_private_key = param_numbers.parameters().generate_private_key()
    server_public_key = server_private_key.public_key()
    server_f = server_public_key.public_numbers().y

    client_public_key = dh.DHPublicNumbers(kex_dh_init.e, param_numbers)
    client_public_key = client_public_key.public_key()

    shared_key = server_private_key.exchange(client_public_key)


    # Send KexDhGexReply message

    assert conn.host_key is not None

    encoded_host_public_key = conn.host_key.encode_public_key()
    encoded_shared_secret = encode_mpint(int.from_bytes(shared_key))

    assert conn.client_ident_string is not None
    assert conn.server_ident_string is not None

    data_to_hash = (
        encode_string(bytes(conn.client_ident_string))
      + encode_string(bytes(conn.server_ident_string))
      + encode_string(client_kex_init_payload)
      + encode_string(server_kex_init_payload)
      + encode_string(encoded_host_public_key)
      + struct.pack('>III', kex_dh_gex_request.min, kex_dh_gex_request.n, kex_dh_gex_request.max)
      + encode_mpint(param_numbers.p)
      + encode_mpint(param_numbers.g)
      + encode_mpint(kex_dh_init.e)
      + encode_mpint(server_f)
      + encoded_shared_secret
    )

    assert conn.algorithm_selection is not None

    exchange_hash = self.hash(data_to_hash)
    signature = conn.host_key.sign_encode(conn.algorithm_selection.server_host_key_algorithm, exchange_hash)

    kex_dh_gex_reply = KexDhGexReplyMessage(
      host_key=encoded_host_public_key,
      f=server_f,
      signature=signature,
    )

    conn.write_message(kex_dh_gex_reply)


    return exchange_hash, shared_key
