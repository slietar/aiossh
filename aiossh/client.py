from abc import ABC


class BaseClient(ABC):
  async def run(self, ident_string: str):
    pass
