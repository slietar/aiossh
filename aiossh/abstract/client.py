from abc import ABC, abstractmethod
from collections.abc import Awaitable
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from ..messages.user_auth import AuthenticationMethodName
from .session import Session, SessionResult


class Client(ABC):
  # Authentication

  @abstractmethod
  async def get_auth_methods(self, user_name: str) -> set[AuthenticationMethodName]:
    ...

  async def auth_with_public_key(self, user_name: str, key: Ed25519PublicKey | RSAPublicKey, *, in_use: bool) -> bool:
    raise NotImplementedError


  # # Session management

  # def set_session_env(self) -> bool:
  #   return True

  # # def start_forwarding(self, handle) -> bool:
  # async def open_tcpip_forward_channel(self, cancelled: Awaitable[None]) -> bool:
  #   ...


  # async def start_exec(self, session: Session, command: str) -> Optional[SessionResult]:
  #   raise NotImplementedError

  # async def start_shell(self, session: Session) -> Optional[SessionResult]:
  #   raise NotImplementedError

  # async def start_subsystem(self, session: Session, name: str) -> None:
  #   raise NotImplementedError
