import asyncio
import os
import signal
from asyncio import StreamReader, StreamWriter

from .connection import Connection


print('PID', os.getpid())

async def serve():
  async def handle_connection_sync(reader: StreamReader, writer: StreamWriter):
    conn = Connection(reader, writer)
    await conn.handle()

  server = await asyncio.start_server(
    handle_connection_sync,
    ['127.0.0.1'],
    port=1302
  )

  await server.serve_forever()


async def main():
  task = asyncio.create_task(serve())

  loop = asyncio.get_event_loop()

  for sig in [signal.SIGINT, signal.SIGTERM]:
    loop.add_signal_handler(sig, task.cancel)

  try:
    await task
  except asyncio.CancelledError:
    pass


asyncio.run(main())
