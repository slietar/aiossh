import typing
from dataclasses import dataclass, field
from typing import Literal, Optional, cast

from .error import AlgorithmNegotiationError
from .messages.kex_init import KexInitMessage
from .public.resolve import SignatureAlgorithmName


type KexAlgorithmName = Literal[
  'curve25519-sha256',
  'curve25519-sha512',
  'diffie-hellman-group-exchange-sha256',
  'ecdh-sha2-nistp256',
  'ecdh-sha2-nistp384',
  'ecdh-sha2-nistp521',
]

type HostKeyAlgorithmName = Literal[
  'ecdsa-sha2-nistp256',
  'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp521',
  'rsa-sha2-256',
  'rsa-sha2-512',
  'ssh-ed25519',
  'ssh-rsa',
]

type EncryptionAlgorithmName = Literal[
  'aes128-ctr',
  'aes192-ctr',
  'aes256-ctr',
]

type MacAlgorithmName = Literal[
  'hmac-sha1',
  'hmac-sha2-256',
  'hmac-sha2-512',
  'umac-32',
  'umac-64',
  'umac-64@openssh.com',
  'umac-96',
  'umac-128',
  'umac-128@openssh.com',
]

type CompressionAlgorithmName = Literal['none']


extract = lambda x: list(typing.get_args(x.__value__))

@dataclass(kw_only=True, slots=True)
class AlgorithmSets:
  kex_algorithms: list[KexAlgorithmName] = field(default_factory=(lambda: extract(KexAlgorithmName)))
  server_host_key_algorithms: list[HostKeyAlgorithmName] = field(default_factory=(lambda: extract(HostKeyAlgorithmName)))
  encryption_algorithms_client_to_server: list[EncryptionAlgorithmName] = field(default_factory=(lambda: extract(EncryptionAlgorithmName)))
  encryption_algorithms_server_to_client: list[EncryptionAlgorithmName] = field(default_factory=(lambda: extract(EncryptionAlgorithmName)))
  mac_algorithms_client_to_server: list[MacAlgorithmName] = field(default_factory=(lambda: extract(MacAlgorithmName)))
  mac_algorithms_server_to_client: list[MacAlgorithmName] = field(default_factory=(lambda: extract(MacAlgorithmName)))
  compression_algorithms_client_to_server: list[CompressionAlgorithmName] = field(default_factory=(lambda: extract(CompressionAlgorithmName)))
  compression_algorithms_server_to_client: list[CompressionAlgorithmName] = field(default_factory=(lambda: extract(CompressionAlgorithmName)))
  languages_client_to_server: set[str] = field(default_factory=set)
  languages_server_to_client: set[str] = field(default_factory=set)


  # See: RFC 4253 Section 7.1

  def negotiate(self, client_message: KexInitMessage):
    kex_algorithm = next((algorithm for algorithm in client_message.kex_algorithms if algorithm in self.kex_algorithms), None)
    server_host_key_algorithm = next((algorithm for algorithm in client_message.server_host_key_algorithms if algorithm in self.server_host_key_algorithms), None)
    encryption_algorithm_client_to_server = next((algorithm for algorithm in client_message.encryption_algorithms_client_to_server if algorithm in self.encryption_algorithms_client_to_server), None)
    encryption_algorithm_server_to_client = next((algorithm for algorithm in client_message.encryption_algorithms_server_to_client if algorithm in self.encryption_algorithms_server_to_client), None)
    mac_algorithm_client_to_server = next((algorithm for algorithm in client_message.mac_algorithms_client_to_server if algorithm in self.mac_algorithms_client_to_server), None)
    mac_algorithm_server_to_client = next((algorithm for algorithm in client_message.mac_algorithms_server_to_client if algorithm in self.mac_algorithms_server_to_client), None)

    assert kex_algorithm not in ('ext-info-c', 'ext-info-s')

    if kex_algorithm is None:
      raise AlgorithmNegotiationError('No common key exchange algorithm found')
    if server_host_key_algorithm is None:
      raise AlgorithmNegotiationError('No common server host key algorithm found')
    if encryption_algorithm_client_to_server is None:
      raise AlgorithmNegotiationError('No common client-to-server encryption algorithm found')
    if encryption_algorithm_server_to_client is None:
      raise AlgorithmNegotiationError('No common server-to-client encryption algorithm found')
    if mac_algorithm_client_to_server is None:
      raise AlgorithmNegotiationError('No common client-to-server MAC algorithm found')
    if mac_algorithm_server_to_client is None:
      raise AlgorithmNegotiationError('No common server-to-client MAC algorithm found')

    return AlgorithmSelection(
      kex_algorithm=cast(KexAlgorithmName, kex_algorithm),
      server_host_key_algorithm=cast(HostKeyAlgorithmName, server_host_key_algorithm),
      encryption_algorithm_client_to_server=cast(EncryptionAlgorithmName, encryption_algorithm_client_to_server),
      encryption_algorithm_server_to_client=cast(EncryptionAlgorithmName, encryption_algorithm_server_to_client),
      mac_algorithm_client_to_server=cast(MacAlgorithmName, mac_algorithm_client_to_server),
      mac_algorithm_server_to_client=cast(MacAlgorithmName, mac_algorithm_server_to_client),
    )


@dataclass(kw_only=True, slots=True)
class AlgorithmSelection:
  kex_algorithm: KexAlgorithmName
  server_host_key_algorithm: HostKeyAlgorithmName
  encryption_algorithm_client_to_server: EncryptionAlgorithmName
  encryption_algorithm_server_to_client: EncryptionAlgorithmName
  mac_algorithm_client_to_server: MacAlgorithmName
  mac_algorithm_server_to_client: MacAlgorithmName


@dataclass(kw_only=True, slots=True)
class ClientExtensions:
  pass

@dataclass(kw_only=True, slots=True)
class ServerExtensions:
  signature_algorithms: Optional[list[SignatureAlgorithmName]] = None
