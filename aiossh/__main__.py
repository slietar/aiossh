import asyncio
import logging
import pickle
import signal
from pathlib import Path

import dexc
from aiodrive import Pool
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from .client import BaseClient
from .host_key import ECDSAHostKey, ED25519HostKey, HostKey, RSAHostKey
from .server import Server
from .tcp import SockName, serve_tcp


# print('PID', os.getpid())
dexc.install()
logging.basicConfig(level=logging.DEBUG)


class Client(BaseClient):
  def __init__(self, name: SockName):
    print(f'New connection from {name}')


async def main():
  host_keys_path = Path('tmp/keys.pkl')

  if host_keys_path.exists():
    with host_keys_path.open('rb') as file:
      host_keys: list[HostKey] = pickle.load(file)
  else:
    host_keys: list[HostKey] = [
      # ED25519HostKey(ed25519.Ed25519PrivateKey.generate()),
      # ECDSAHostKey(ec.generate_private_key(ec.SECP256R1())),
      RSAHostKey(private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048), supported_algorithms=frozenset({'ssh-rsa', 'rsa-sha2-256'}))
    ]

    host_keys_path.parent.mkdir(exist_ok=True, parents=True)

    with host_keys_path.open('wb') as file:
      pickle.dump(host_keys, file)

  # pprint(host_keys)
  server = Server(host_keys=host_keys)


  async with serve_tcp(['127.0.0.1', '::1'], 1302) as tcp_server:
    for name in tcp_server.names:
      print(f'Listening on {name}')

    async with Pool.open() as pool:
      async for incoming in tcp_server:
        pool.spawn(
          server.handle(
            Client(incoming.client_name),
            incoming.reader,
            incoming.writer
          ),
          name=f'handle-{incoming.client_name}'
        )


async def entry():
  task = asyncio.create_task(main())
  loop = asyncio.get_event_loop()

  for sig in [signal.SIGINT, signal.SIGTERM]:
    loop.add_signal_handler(sig, task.cancel)

  try:
    await task
  except asyncio.CancelledError:
    print('[Interrupted]')


asyncio.run(entry())
