import hashlib
import logging
import struct
from dataclasses import dataclass
from typing import override

from cryptography.hazmat.primitives.asymmetric import dh

from ..error import ProtocolError
from ..flow import MessageFlow
from ..messages.key_exchange import (
  KexDhGexGroupMessage,
  KexDhGexInitMessage,
  KexDhGexReplyMessage,
  KexDhGexRequestMessage,
)
from ..primes.group import select_group
from ..structures.primitives import encode_mpint, encode_string
from .base import KeyExchange


LOGGER = logging.getLogger(__name__)


# See: RFC 4419

@dataclass(slots=True)
class DhKeyExchange(KeyExchange):
  @override
  def hash(self, data: bytes, /) -> bytes:
    return hashlib.sha256(data).digest()

  @override
  def run_as_server(
    self,
    conn,
    algorithm_selection,
    host_key,
    hash_header,
  ) -> MessageFlow[tuple[bytes, bytes]]:
    # Receive KexDhGexRequest message

    kex_dh_gex_request = (yield).decode(KexDhGexRequestMessage)

    if not (
      (kex_dh_gex_request.min <= kex_dh_gex_request.n <= kex_dh_gex_request.max)
      and (kex_dh_gex_request.max >= 1024)
    ):
      raise ProtocolError

    # The p and g parameter numbers can be reused.
    # See: https://crypto.stackexchange.com/a/2019

    # It is important to use the well-known groups because OpenSSL, which is used as cryptography's backend, knows them and can skip checks.
    # See: https://github.com/openssl/openssl/blob/311f7bd6dd609cd32faa406bbddca580ae4fd4eb/crypto/dh/dh_group_params.c#L56

    group = select_group(
      conn._dh_groups,
      min(kex_dh_gex_request.min, 1024),
      kex_dh_gex_request.n,
      kex_dh_gex_request.max,
    )

    if group is None:
      raise ProtocolError

    param_numbers = dh.DHParameterNumbers(p=group.prime, g=group.generator)

    LOGGER.debug(f'Selected group with {group.size} bits')


    # Receive KexDhGexGroup message

    conn._send_message(
      KexDhGexGroupMessage(p=param_numbers.p, g=param_numbers.g),
    )

    kex_dh_init = (yield).decode(KexDhGexInitMessage)

    server_private_key = param_numbers.parameters().generate_private_key()
    server_public_key = server_private_key.public_key()
    server_f = server_public_key.public_numbers().y

    client_public_key = dh.DHPublicNumbers(kex_dh_init.e, param_numbers)
    client_public_key = client_public_key.public_key()

    shared_key = server_private_key.exchange(client_public_key)


    # Send KexDhGexReply message

    encoded_host_public_key = host_key.to_public_key().encode()
    encoded_shared_secret = encode_mpint(int.from_bytes(shared_key))

    data_to_hash = (
      hash_header
      + encode_string(encoded_host_public_key)
      + struct.pack('>III', kex_dh_gex_request.min, kex_dh_gex_request.n, kex_dh_gex_request.max)
      + encode_mpint(param_numbers.p)
      + encode_mpint(param_numbers.g)
      + encode_mpint(kex_dh_init.e)
      + encode_mpint(server_f)
      + encoded_shared_secret
    )

    exchange_hash = self.hash(data_to_hash)
    signature = host_key.sign_encode(algorithm_selection.server_host_key_algorithm, exchange_hash)

    conn._send_message(
      KexDhGexReplyMessage(
        host_key=encoded_host_public_key,
        f=server_f,
        signature=signature,
      ),
    )

    return exchange_hash, shared_key
