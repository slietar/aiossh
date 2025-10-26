import asyncio
import logging
import os
import pickle
import signal
from asyncio import TaskGroup
from pathlib import Path

import aiodrive
from cryptography.hazmat.primitives.asymmetric import rsa

from .client import BaseClient
from .host_key import HostKey, RSAHostKey
from .server import Server
from .tcp import SockName, serve_tcp


logging.basicConfig(
  format='[%(levelname)s] %(name)s    %(message)s',
  level=logging.DEBUG,
)

logger = logging.getLogger('__main__')
logger.debug(f'Process id: {os.getpid()}')


class Client(BaseClient):
  def __init__(self, name: SockName):
    logger.debug(f'New connection from {name}')


async def main():
  # Load or generate host keys

  host_keys_path = Path('tmp/keys.pkl')

  if host_keys_path.exists():
    with host_keys_path.open('rb') as file:
      host_keys: list[HostKey] = pickle.load(file)
  else:
    host_keys: list[HostKey] = [
      # ED25519HostKey(ed25519.Ed25519PrivateKey.generate()),
      # ECDSAHostKey(ec.generate_private_key(ec.SECP256R1())),
      RSAHostKey(
        private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
        supported_algorithms=frozenset({'ssh-rsa', 'rsa-sha2-256'}),
      ),
    ]

    host_keys_path.parent.mkdir(exist_ok=True, parents=True)

    with host_keys_path.open('wb') as file:
      pickle.dump(host_keys, file)


  # Start server

  server = Server(host_keys=host_keys)

  try:
    with aiodrive.handle_signal(signal.SIGINT, signal.SIGTERM):
      async with serve_tcp(['127.0.0.1', '::1'], 1302) as tcp_server:
        for name in tcp_server.names:
          logger.info(f'Listening on {name}')

        async with TaskGroup() as group:
          async for incoming in tcp_server:
            group.create_task(
              server.handle(
                Client(incoming.client_name),
                incoming.reader,
                incoming.writer,
              ),
              name=f'handle-{incoming.client_name}',
            )
  except aiodrive.SignalHandledException as e:
    print('\r', end='')
    logger.info(f'Received {signal.Signals(e.signal).name}')


asyncio.run(main())
