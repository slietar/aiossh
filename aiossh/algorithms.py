import typing
from dataclasses import dataclass, field
from typing import Literal, cast

from .error import AlgorithmNegotiationError, ProtocolError

from .messages.kex_init import KexInitMessage


type KexAlgorithmName = Literal['diffie-hellman-group-exchange-sha256']
type HostKeyAlgorithmName = Literal['ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'rsa-sha2-256', 'rsa-sha2-512']
type EncryptionAlgorithmName = Literal['aes128-ctr', 'aes192-ctr', 'aes256-ctr']
type MacAlgorithmName = Literal['hmac-sha1', 'hmac-sha2-256']
type CompressionAlgorithmName = Literal['none']


extract = lambda x: set(typing.get_args(x.__value__))

@dataclass(kw_only=True, slots=True)
class AlgorithmSets:
  kex_algorithms: set[KexAlgorithmName] = field(default_factory=(lambda: extract(KexAlgorithmName)))
  server_host_key_algorithms: set[HostKeyAlgorithmName] = field(default_factory=(lambda: extract(HostKeyAlgorithmName)))
  encryption_algorithms_client_to_server: set[EncryptionAlgorithmName] = field(default_factory=(lambda: extract(EncryptionAlgorithmName)))
  encryption_algorithms_server_to_client: set[EncryptionAlgorithmName] = field(default_factory=(lambda: extract(EncryptionAlgorithmName)))
  mac_algorithms_client_to_server: set[MacAlgorithmName] = field(default_factory=(lambda: extract(MacAlgorithmName)))
  mac_algorithms_server_to_client: set[MacAlgorithmName] = field(default_factory=(lambda: extract(MacAlgorithmName)))
  compression_algorithms_client_to_server: set[CompressionAlgorithmName] = field(default_factory=(lambda: extract(CompressionAlgorithmName)))
  compression_algorithms_server_to_client: set[CompressionAlgorithmName] = field(default_factory=(lambda: extract(CompressionAlgorithmName)))
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
      mac_algorithm_server_to_client=cast(MacAlgorithmName, mac_algorithm_server_to_client)
    )


@dataclass(kw_only=True, slots=True)
class AlgorithmSelection:
  kex_algorithm: KexAlgorithmName
  server_host_key_algorithm: HostKeyAlgorithmName
  encryption_algorithm_client_to_server: EncryptionAlgorithmName
  encryption_algorithm_server_to_client: EncryptionAlgorithmName
  mac_algorithm_client_to_server: MacAlgorithmName
  mac_algorithm_server_to_client: MacAlgorithmName
