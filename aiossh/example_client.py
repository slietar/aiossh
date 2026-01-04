import logging
import os
from asyncio import TaskGroup
from pathlib import Path
from typing import override

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import ssh_key_fingerprint

from .abstract.client import Client
from .abstract.session import SessionExitStatus
from .error import UnreachableError
from .messages.user_auth import AuthenticationMethodName
from .pty import PTYSession, iter_reader


logger = logging.getLogger(__name__)


class ExampleClient(Client):
  @override
  async def get_auth_methods(self, user_name) -> set[AuthenticationMethodName]:
    return {'publickey'}

  @override
  async def auth_with_public_key(self, user_name, key, *, in_use) -> bool:
    match key:
      case Ed25519PublicKey():
        key_type = 'ED25519'
      case RSAPublicKey():
        key_type = 'RSA'
      case _:
        raise UnreachableError

    authorized_fingerprints = {
      bytes.fromhex(string.replace(':', '')) for string in {
        # ED25519
        'c3:8c:25:d4:54:6c:4d:f4:6c:ec:87:35:b1:6c:31:98:2e:92:72:25:7b:63:1e:41:76:4b:fc:1b:d3:88:ee:f8',

        # RSA
        '90:60:a3:72:6b:2f:bf:db:7f:16:54:d5:a1:f3:cb:da:a0:6b:bb:ba:79:5e:35:1c:ef:46:66:26:e5:c7:72:b9',
      }
    }

    fingerprint = ssh_key_fingerprint(key, hash_algorithm=SHA256())

    if fingerprint in authorized_fingerprints:
      if in_use:
        logger.debug(f'Authenticated user "{user_name}" with public {key_type} key fingerprint {fingerprint.hex(':')}')

      return True
    else:
      logger.debug(f'Public key authentication failed for user "{user_name}" with public {key_type} key fingerprint {fingerprint.hex(':')}')
      return False

  @override
  async def start_shell(self, session):
    assert session.settings.pty is not None
    assert session.activity is not None

    activity = session.activity

    # return SessionExitStatus(3)

    async def pipe_stdin_to_pty(pty_session: PTYSession):
      async for chunk in iter_reader(activity.stdin):
        pty_session.write(chunk)

    async def pipe_pty_to_stdout(pty_session: PTYSession):
      async for chunk in iter_reader(pty_session.reader):
        await activity.stdout.write(chunk)

    # async def watch_terminal_size(session: PTYSession):
    #   while True:
    #     await aiodrive.wait_for_signal(signal.SIGWINCH)
    #     session.resize(os.get_terminal_size())


    # pty_session = None

    async with PTYSession.create(
      os.environ['SHELL'],
      cwd=Path.home(),
      env=session.settings.env,
      terminal_size=os.terminal_size(session.settings.pty.window_chars),
    ) as pty_session:
      async with TaskGroup() as group:
        group.create_task(pipe_pty_to_stdout(pty_session))
        group.create_task(pipe_stdin_to_pty(pty_session))
        # group.create_task(watch_terminal_size(session))


    # if pty_session is not None:
    #   return SessionExitStatus(pty_session.process.returncode)
