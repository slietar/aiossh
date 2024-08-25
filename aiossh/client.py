from abc import ABC

from .algorithms import AlgorithmSets


class BaseClient(ABC):
  def get_supported_algorithms(self):
    return AlgorithmSets()

  async def run(self, ident_string: str):
    pass
