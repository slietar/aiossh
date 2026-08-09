import asyncio
from asyncio import Event, Task
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Optional, Protocol

import aiodrive

from ...connection import Connection
from ...error import ConnectionTerminatedError
from ...events import (
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


class AsyncSessionClient(Protocol):
  async def resize(self, window_chars: tuple[int, int], window_pixels: tuple[int, int], /) -> None:
    ...

  async def run(self, stream: AsyncStream) -> None:
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

  async def start_exec_session(self, command: str, env: Mapping[str, str], pty: Optional[SessionPTYOptions]) -> Optional[AsyncSessionClient]:
    ...

  async def start_shell_session(self, env: Mapping[str, str], pty: Optional[SessionPTYOptions]) -> Optional[AsyncSessionClient]:
    ...


@dataclass(slots=True)
class AsyncStream:
  read: Callable[[], Awaitable[bytes]]
  _send_buffer_nonfull_event: Event
  _send_trigger: Event
  _stream: Stream

  def exit(self, code: int):
    self._stream.exit(code)
    self._send_trigger.set()

  async def write(self, data: bytes, /, *, error: bool = False):
    buffer = data

    while buffer:
      await self._send_buffer_nonfull_event.wait()

      self._stream.write(buffer[:self._stream.window_size], error=error)
      self._send_trigger.set()

      buffer = buffer[self._stream.window_size:]

      if self._stream.window_size == 0:
        self._send_buffer_nonfull_event.clear()

  @property
  def window_size(self):
    return self._stream.window_size


@dataclass(slots=True)
class Session:
  buffer: bytes = field(default=b'', init=False)
  buffer_event: Event = field(default_factory=Event, init=False)
  received_eof: bool = field(default=False, init=False)
  send_buffer_nonfull_event: Event

  client: AsyncSessionClient
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

            case SessionExecEvent() | SessionShellEvent():
              async def handle_session_exec_event(event: SessionExecEvent | SessionShellEvent):
                if isinstance(event, SessionExecEvent):
                  session_client = await client.start_exec_session(
                    event.command,
                    event.env,
                    event.pty,
                  )
                else:
                  session_client = await client.start_shell_session(
                    event.env,
                    event.pty,
                  )

                if session_client is not None:
                  async def session_read(size: Optional[int] = None):
                    session = sessions[event.channel_id]

                    if session.received_eof:
                      return b''

                    await session.buffer_event.wait()

                    effective_size = size if size is not None else len(session.buffer)

                    chunk = session.buffer[:effective_size]
                    session.buffer = session.buffer[effective_size:]

                    if not session.buffer:
                      session.buffer_event.clear()

                    stream.reset_window()
                    send_trigger.set()

                    return chunk

                  stream = event.accept()

                  send_buffer_nonfull_event = Event()
                  send_buffer_nonfull_event.set()

                  task = group.create_task(
                    session_client.run(
                      AsyncStream(
                        read=session_read,
                        _send_buffer_nonfull_event=send_buffer_nonfull_event,
                        _send_trigger=send_trigger,
                        _stream=stream,
                      ),
                    ),
                  )

                  sessions[event.channel_id] = Session(
                    client=session_client,
                    send_buffer_nonfull_event=send_buffer_nonfull_event,
                    task=task,
                  )
                else:
                  event.reject()

                send_trigger.set()

              group.create_task(handle_session_exec_event(event))


            # Session data processing

            case ChannelDataEvent():
              session = sessions[event.channel_id]
              session.buffer += event.chunk
              session.buffer_event.set()

            case ChannelEofEvent():
              session = sessions[event.channel_id]
              session.received_eof = True
              session.buffer_event.set()

            case ChannelWindowAdjustEvent():
              session = sessions[event.channel_id]
              session.send_buffer_nonfull_event.set()

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
