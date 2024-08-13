import asyncio
import os
import pickle
from pprint import pprint
import signal
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from .host_key import ECDSAHostKey, ED25519HostKey, HostKey
from .server import Server


print('PID', os.getpid())

async def main():
  host_keys_path = Path('tmp/keys.pkl')

  if host_keys_path.exists():
    with host_keys_path.open('rb') as file:
      host_keys: list[HostKey] = pickle.load(file)
  else:
    host_keys: list[HostKey] = [
      ED25519HostKey(ed25519.Ed25519PrivateKey.generate()),
      ECDSAHostKey(ec.generate_private_key(ec.SECP256R1())),
    ]

    host_keys_path.parent.mkdir(exist_ok=True, parents=True)

    with host_keys_path.open('wb') as file:
      pickle.dump(host_keys, file)

  pprint(host_keys)
  server = Server(host_keys=host_keys)

  task = asyncio.create_task(server.serve('127.0.0.1', 1302))
  loop = asyncio.get_event_loop()

  for sig in [signal.SIGINT, signal.SIGTERM]:
    loop.add_signal_handler(sig, task.cancel)

  try:
    await task
  except asyncio.CancelledError:
    pass


asyncio.run(main())
