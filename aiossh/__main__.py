import asyncio
import logging
import os
import pickle
import signal
from pathlib import Path

import aiodrive

from .connection_sansio import SansIOConnection, SansIOConnectionSettings
from .error import ConnectionTerminatedError
from .events import (
  AuthWithPasswordRequestEvent,
  AuthWithPublicKeyRequestEvent,
  ChannelDataEvent,
  ChannelEofEvent,
  DataEvent,
  ChannelOpenEvent,
  SessionExecEvent,
)
from .public.base import PrivateKey
from .public.rsa import RSAPrivateKey


LOGGER = logging.getLogger(__name__)


def get_host_keys():

  host_keys_path = Path('tmp/keys.pkl')

  if host_keys_path.exists():
    with host_keys_path.open('rb') as file:
      host_keys: list[PrivateKey] = pickle.load(file)
  else:
    host_keys: list[PrivateKey] = [
      RSAPrivateKey.generate(),
    ]

    host_keys_path.parent.mkdir(exist_ok=True, parents=True)

    with host_keys_path.open('wb') as file:
      pickle.dump(host_keys, file)

  return host_keys

async def main():
  LOGGER.debug(f'Process id: {os.getpid()}')

  async def tcp_handler(tcp_connection: aiodrive.Connection):
    LOGGER.debug(f'Incoming connection from {tcp_connection.client_name} to {tcp_connection.server_name}')

    conn = SansIOConnection(
      debug=True,
      settings=SansIOConnectionSettings(
        host_keys=get_host_keys(),
        software_version='aiossh_0.0.0',
        supported_auth_methods=['publickey'],
      ),
    )

    stream = None

    while True:
      # LOGGER.debug('Enumerating events...')

      try:
        for event in conn.events():
          match event:
            case DataEvent(chunk):
              tcp_connection.writer.write(chunk)
              await tcp_connection.writer.drain()
            case AuthWithPasswordRequestEvent(user_name=user_name, password=password, respond=respond):
              print(f'Auth with password request for user "{user_name}" with password "{password}"')
              respond(True)
            case AuthWithPublicKeyRequestEvent(user_name=user_name, algorithm=algorithm, public_key=public_key, authenticating=authenticating, respond=respond):
              print(f'Auth with public key request for user "{user_name}" with algorithm "{algorithm}" and public key "{public_key.hex()}" (authenticating={authenticating})')
              respond(True)
            case ChannelOpenEvent():
              channel_id = event.accept()
              print(f'Accepted open channel request with channel id {channel_id}')
            case SessionExecEvent(command=command):
              print(f'Session exec request with command "{command}"')
              stream = event.accept()
              # stream.write(b'Hello, world!\n')
              # stream.exit(7)
            case ChannelDataEvent(channel_id=channel_id, chunk=chunk):
              assert stream is not None
              stream.write(chunk)
            case ChannelEofEvent(channel_id=channel_id):
              assert stream is not None
              stream.exit(7)
            case _:
              print('Event:', event)


        # LOGGER.debug('Waiting for data...')
        chunk = await tcp_connection.reader.read(65_536)

        if not chunk:
          break

        conn.feed(chunk)
      except ConnectionTerminatedError:
        LOGGER.debug('Connection terminated')
        break


  try:
    with aiodrive.handle_signal([signal.SIGINT, signal.SIGTERM]):
      async with aiodrive.TCPServer.listen(
        tcp_handler,
        host=['127.0.0.1', '::1'],
        port=1302,
      ) as tcp_server:
        for binding in tcp_server.bindings:
          LOGGER.info(f'Listening on {binding}')

        await aiodrive.wait_forever()
  except aiodrive.SignalHandledException as e:
    print('\r', end='')
    LOGGER.info(f'Received {signal.Signals(e.signal).name}')


if __name__ == '__main__':
  logging.basicConfig(
    format='[%(levelname)s] %(name)s    %(message)s',
    level=logging.DEBUG,
  )

  asyncio.run(main())
