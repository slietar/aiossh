import asyncio
import logging
import os
import pickle
import signal
from pathlib import Path

import aiodrive

from .example_client import ExampleClient
from .public.base import PrivateKey
from .public.rsa import RSAPrivateKey
from .server import Server


logging.basicConfig(
  format='[%(levelname)s] %(name)s    %(message)s',
  level=logging.DEBUG,
)

logger = logging.getLogger('__main__')
logger.debug(f'Process id: {os.getpid()}')


async def main():
  # Load or generate host keys

  host_keys_path = Path('tmp/keys.pkl')

  if host_keys_path.exists():
    with host_keys_path.open('rb') as file:
      host_keys: list[PrivateKey] = pickle.load(file)
  else:
    host_keys: list[PrivateKey] = [
      # ED25519HostKey(ed25519.Ed25519PrivateKey.generate()),
      # ECDSAHostKey(ec.generate_private_key(ec.SECP256R1())),
      RSAPrivateKey.generate(),
    ]

    host_keys_path.parent.mkdir(exist_ok=True, parents=True)

    with host_keys_path.open('wb') as file:
      pickle.dump(host_keys, file)


  # Start server

  ssh_server = Server(host_keys=host_keys)

  async def tcp_handler(tcp_connection: aiodrive.Connection):
    logger.debug(f'Incoming connection from {tcp_connection.client_name} to {tcp_connection.server_name}')

    await ssh_server.handle(
      ExampleClient(),
      tcp_connection.reader,
      tcp_connection.writer,
    )

  try:
    with aiodrive.handle_signal([signal.SIGINT, signal.SIGTERM]):
      async with aiodrive.TCPServer.listen(
        tcp_handler,
        host=['127.0.0.1', '::1'],
        port=1302,
      ) as tcp_server:
        for binding in tcp_server.bindings:
          logger.info(f'Listening on {binding}')

        await aiodrive.wait_forever()
  except aiodrive.SignalHandledException as e:
    print('\r', end='')
    logger.info(f'Received {signal.Signals(e.signal).name}')


asyncio.run(main())
