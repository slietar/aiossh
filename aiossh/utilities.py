from collections.abc import Generator
from dataclasses import dataclass, field


@dataclass(slots=True)
class GeneratorWrapper[Yield, Send, Return]:
  inner: Generator[Yield, Send]
  value: Return = field(init=False)

  def __init__(self, generator: Generator[Yield, Send, Return], /):
    self.inner = self._it(generator).__iter__()

  def send(self, value: Send):
    return self.inner.send(value)

  def _it(self, generator: Generator[Yield, Send, Return], /):
    self.value = yield from generator

  def __next__(self):
    return next(self.inner)
