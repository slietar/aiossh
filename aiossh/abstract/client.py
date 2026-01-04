from abc import ABC, abstractmethod
from collections.abc import Awaitable
from typing import Optional

from ..messages.user_auth import AuthenticationMethodName
from ..public.base import PublicKey
from ..session import Session
from .session import SessionResult


class Client(ABC):
  # Authentication

  @abstractmethod
  async def get_auth_methods(self, user_name: str) -> set[AuthenticationMethodName]:
    ...

  async def auth_with_public_key(self, user_name: str, key: PublicKey, *, in_use: bool) -> bool:
    raise NotImplementedError


  # Session management

  def set_session_env(self, key: str, value: str) -> bool:
    return True

  # # def start_forwarding(self, handle) -> bool:
  # async def open_tcpip_forward_channel(self, cancelled: Awaitable[None]) -> bool:
  #   ...


  def start_exec(self, session: Session, command: str) -> Awaitable[Optional[SessionResult]]:
    raise NotImplementedError

  def start_shell(self, session: Session) -> Awaitable[Optional[SessionResult]]:
    raise NotImplementedError

  # async def start_subsystem(self, session: Session, name: str) -> None:
  #   raise NotImplementedError
