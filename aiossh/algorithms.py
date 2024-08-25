import typing
from dataclasses import dataclass
from typing import Literal, cast

from .error import ProtocolError

from .messages.kex_init import KexInitMessage


type KexAlgorithmName = Literal['diffie-hellman-group-exchange-sha256']
type HostKeyAlgorithmName = Literal['ssh-ed25519', 'ecdsa-sha2-nistp256']
type EncryptionAlgorithmName = Literal['aes128-ctr', 'aes192-ctr', 'aes256-ctr']
type MacAlgorithmName = Literal['hmac-sha1', 'hmac-sha2-256']
type CompressionAlgorithmName = Literal['none']


# @dataclass(slots=True)
# class AlgorithmLists:
#   kex_algorithms: list[KexAlgorithm]
#   server_host_key_algorithms: list[HostKeyAlgorithm]
#   encryption_algorithms_client_to_server: list[EncryptionAlgorithm]
#   encryption_algorithms_server_to_client: list[EncryptionAlgorithm]
#   mac_algorithms_client_to_server: list[MacAlgorithm]
#   mac_algorithms_server_to_client: list[MacAlgorithm]
#   compression_algorithms_client_to_server: list[CompressionAlgorithm]
#   compression_algorithms_server_to_client: list[CompressionAlgorithm]
#   languages_client_to_server: list[str]
#   languages_server_to_client: list[str]


extract = lambda x: frozenset(typing.get_args(x.__value__))

@dataclass(kw_only=True, slots=True)
class AlgorithmSets:
  kex_algorithms: frozenset[KexAlgorithmName] = extract(KexAlgorithmName)
  server_host_key_algorithms: frozenset[HostKeyAlgorithmName] = extract(HostKeyAlgorithmName)
  encryption_algorithms_client_to_server: frozenset[EncryptionAlgorithmName] = extract(EncryptionAlgorithmName)
  encryption_algorithms_server_to_client: frozenset[EncryptionAlgorithmName] = extract(EncryptionAlgorithmName)
  mac_algorithms_client_to_server: frozenset[MacAlgorithmName] = extract(MacAlgorithmName)
  mac_algorithms_server_to_client: frozenset[MacAlgorithmName] = extract(MacAlgorithmName)
  compression_algorithms_client_to_server: frozenset[CompressionAlgorithmName] = extract(CompressionAlgorithmName)
  compression_algorithms_server_to_client: frozenset[CompressionAlgorithmName] = extract(CompressionAlgorithmName)
  languages_client_to_server: frozenset[str] = frozenset()
  languages_server_to_client: frozenset[str] = frozenset()

  # def __and__(self, other: 'AlgorithmSets'):
  #   return AlgorithmSets(
  #     kex_algorithms=(self.kex_algorithms & other.kex_algorithms),
  #     server_host_key_algorithms=(self.server_host_key_algorithms & other.server_host_key_algorithms),
  #     encryption_algorithms_client_to_server=(self.encryption_algorithms_client_to_server & other.encryption_algorithms_client_to_server),
  #     encryption_algorithms_server_to_client=(self.encryption_algorithms_server_to_client & other.encryption_algorithms_server_to_client),
  #     mac_algorithms_client_to_server=(self.mac_algorithms_client_to_server & other.mac_algorithms_client_to_server),
  #     mac_algorithms_server_to_client=(self.mac_algorithms_server_to_client & other.mac_algorithms_server_to_client),
  #     compression_algorithms_client_to_server=(self.compression_algorithms_client_to_server & other.compression_algorithms_client_to_server),
  #     compression_algorithms_server_to_client=(self.compression_algorithms_server_to_client & other.compression_algorithms_server_to_client),
  #     languages_client_to_server=(self.languages_client_to_server & other.languages_client_to_server),
  #     languages_server_to_client=(self.languages_server_to_client & other.languages_server_to_client)
  #   )


  # See: RFC 4253 Section 7.1

  def negotiate(self, client_message: KexInitMessage):
    kex_algorithm = next((algorithm for algorithm in client_message.kex_algorithms if algorithm in self.kex_algorithms), None)
    server_host_key_algorithm = next((algorithm for algorithm in client_message.server_host_key_algorithms if algorithm in self.server_host_key_algorithms), None)
    encryption_algorithm_client_to_server = next((algorithm for algorithm in client_message.encryption_algorithms_client_to_server if algorithm in self.encryption_algorithms_client_to_server), None)
    encryption_algorithm_server_to_client = next((algorithm for algorithm in client_message.encryption_algorithms_server_to_client if algorithm in self.encryption_algorithms_server_to_client), None)
    mac_algorithm_client_to_server = next((algorithm for algorithm in client_message.mac_algorithms_client_to_server if algorithm in self.mac_algorithms_client_to_server), None)
    mac_algorithm_server_to_client = next((algorithm for algorithm in client_message.mac_algorithms_server_to_client if algorithm in self.mac_algorithms_server_to_client), None)

    if (kex_algorithm is None)\
      or (server_host_key_algorithm is None)\
      or (encryption_algorithm_client_to_server is None)\
      or (encryption_algorithm_server_to_client is None)\
      or (mac_algorithm_client_to_server is None)\
      or (mac_algorithm_server_to_client is None):
      raise ProtocolError('Algorithm negotiation failure')

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
