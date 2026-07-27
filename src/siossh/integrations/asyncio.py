import asyncio
from asyncio import Event, Task
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Optional, Protocol

import aiodrive

from ..connection import Connection
from ..error import ConnectionTerminatedError
from ..events import (
  AuthWithPasswordRequestEvent,
  AuthWithPublicKeyRequestEvent,
  ChannelCloseEvent,
  ChannelDataEvent,
  ChannelEofEvent,
  ChannelOpenEvent,
  ChannelWindowAdjustEvent,
  DisconnectEvent,
  PTYSessionTerminalSizeChangeEvent,
  SessionExecEvent,
  SessionPTYOptions,
  SessionShellEvent,
  Stream,
)


class SessionClient(Protocol):
  async def receive(self, chunk: bytes, /) -> None:
    ...

  async def resize(self, window_chars: tuple[int, int], window_pixels: tuple[int, int], /) -> None:
    ...

  async def run(self, stream: Stream) -> None:
    ...


class AsyncConnectionClient(Protocol):
  async def auth_with_password(self, name: str, password: str) -> bool:
    ...

  async def auth_with_public_key(self, name: str, public_key: bytes, authenticating: bool) -> bool:
    ...

  async def close(self) -> None:
    ...

  async def disconnect(self, reason: int, description: str) -> None:
    ...

  async def start_exec_session(self, command: str, env: Mapping[str, str], pty: Optional[SessionPTYOptions]) -> Optional[SessionClient]:
    ...

  async def start_shell_session(self, env: Mapping[str, str], pty: Optional[SessionPTYOptions]) -> Optional[SessionClient]:
    ...


@dataclass(slots=True)
class Session:
  client: SessionClient
  task: Task[None]

async def attach_async_client(
  conn: Connection,
  client: AsyncConnectionClient,
  *,
  read: Callable[[], Awaitable[bytes]],
  write: Callable[[bytes], Awaitable[None]],
):
  event_trigger = Event()
  send_trigger = Event()
  sessions = dict[int, Session]()

  async def send_loop():
    while True:
      while (chunk := conn.get_send_buffer(65_536)):
        await write(chunk)

      await send_trigger.wait()
      send_trigger.clear()


  try:
    async with aiodrive.volatile_task_group() as group:
      group.create_task(send_loop())

      while True:
        for event in conn.events():
          match event:
            # General

            case DisconnectEvent():
              if event.other:
                await client.disconnect(event.reason, event.description)

              return


            # Authentication

            case AuthWithPasswordRequestEvent():
              event.respond(
                await client.auth_with_password(
                  event.user_name,
                  event.password,
                ),
              )

            case AuthWithPublicKeyRequestEvent():
              event.respond(
                await client.auth_with_public_key(
                  event.user_name,
                  event.public_key,
                  event.authenticating,
                ),
              )


            # Channel opening and closing

            case ChannelCloseEvent():
              if event.channel_id in sessions:
                del sessions[event.channel_id]

            case ChannelOpenEvent():
              event.accept()


            # Session initialization

            case SessionExecEvent():
              async def handle_session_exec_event(event: SessionExecEvent):
                session_client = await client.start_exec_session(
                  event.command,
                  event.env,
                  event.pty,
                )

                if session_client is not None:
                  stream = event.accept()
                  task = asyncio.create_task(session_client.run(stream))
                  sessions[event.channel_id] = Session(client=session_client, task=task)
                else:
                  event.reject()

                send_trigger.set()

              group.create_task(handle_session_exec_event(event))

            case SessionShellEvent():
              async def handle_session_shell_event(event: SessionShellEvent):
                session_client = await client.start_shell_session(
                  event.env,
                  event.pty,
                )

                if session_client is not None:
                  stream = event.accept()
                  task = asyncio.create_task(session_client.run(stream))
                  sessions[event.channel_id] = Session(client=session_client, task=task)
                else:
                  event.reject()

                send_trigger.set()

              group.create_task(handle_session_shell_event(event))


            # Session data processing

            case ChannelDataEvent():
              session = sessions[event.channel_id]
              await session.client.receive(event.chunk)

            case ChannelEofEvent():
              session = sessions[event.channel_id]
              await session.client.receive(b'')

            case ChannelWindowAdjustEvent():
              pass

            case PTYSessionTerminalSizeChangeEvent():
              session = sessions[event.channel_id]
              await session.client.resize(
                event.window_chars,
                event.window_pixels,
              )

        send_trigger.set()

        try:
          index, chunk = await aiodrive.race(
            read(),
            event_trigger.wait(),
          )
        except asyncio.CancelledError:
          conn.close()
          raise
        except ConnectionError:
          await client.close()
          return

        event_trigger.clear()

        if index == 0:
          assert isinstance(chunk, bytes)

          conn.feed(chunk)
          send_trigger.set()

  except* ConnectionTerminatedError:
    pass
  finally:
    await aiodrive.shield_wait(client.close())
