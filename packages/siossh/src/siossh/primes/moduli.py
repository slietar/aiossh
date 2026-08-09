from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from os import PathLike
from pathlib import Path
from typing import IO, Literal, Optional, cast


# See: man moduli

type PrimeType = Literal['safe', 'sophie_germain', 'unknown']

@dataclass(frozen=True, kw_only=True, slots=True)
class GroupRecord:
  generator: int
  prime: int = field(repr=False)
  size: int
  test_composite: bool
  test_probabilistic: bool
  test_sieve: bool
  time: datetime
  type: PrimeType


def load_paths(paths: Optional[Iterable[PathLike | str]] = None):
  if paths is None:
    paths = [
      '/etc/ssh/moduli',
      '/usr/local/etc/moduli',
    ]

  for raw_path in paths:
    path = Path(raw_path)

    if path.exists():
      with path.open('r') as file:
        yield from load_file(file)

      break
  else:
    raise FileNotFoundError('No moduli file found')


def load_file(file: IO[str]):
  for line in file:
    if line[0] == '#':
      continue

    (
      raw_timestamp,
      raw_prime_time,
      raw_tests,
      _tries,
      raw_size,
      raw_generator,
      modulus,
    ) = line.rstrip().split()

    tests = int(raw_tests)

    yield GroupRecord(
      generator=int(raw_generator),
      prime=int(modulus, 16),
      size=int(raw_size),
      test_composite=((tests & 0x01) > 0),
      test_probabilistic=((tests & 0x04) > 0),
      test_sieve=((tests & 0x02) > 0),
      time=datetime.strptime(raw_timestamp, '%Y%m%d%H%M%S'),
      type=cast(PrimeType, {
        0: 'unknown',
        2: 'safe',
        4: 'sophie_germain',
      }[int(raw_prime_time)]),
    )
