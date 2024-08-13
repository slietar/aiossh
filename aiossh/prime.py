from dataclasses import dataclass, field
from datetime import datetime
import os
from pathlib import Path
from typing import IO, Iterable, Literal, Optional, cast


# See: man moduli

type PrimeType = Literal['safe', 'sophie_germain', 'unknown']

@dataclass(frozen=True, kw_only=True, slots=True)
class Prime:
  generator: int
  size: int
  test_composite: bool
  test_probabilistic: bool
  test_sieve: bool
  time: datetime
  type: PrimeType
  value: int = field(repr=False)


def load_paths(paths: Optional[Iterable[os.PathLike | str]] = None):
  if paths is None:
    paths = [
      '/etc/ssh/moduli',
      '/usr/local/etc/moduli'
    ]

  for raw_path in paths:
    path = Path(raw_path)

    if path.exists():
      with path.open('r') as file:
        for prime in load_file(file):
          yield prime

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
      tries,
      raw_size,
      raw_generator,
      modulus,
    ) = line.rstrip().split()

    tests = int(raw_tests)

    yield Prime(
      generator=int(raw_generator),
      size=int(raw_size),
      test_composite=((tests & 0x01) > 0),
      test_probabilistic=((tests & 0x04) > 0),
      test_sieve=((tests & 0x02) > 0),
      time=datetime.strptime(raw_timestamp, '%Y%m%d%H%M%S'),
      type=cast(PrimeType, {
        0: 'unknown',
        2: 'safe',
        4: 'sophie_germain'
      }[int(raw_prime_time)]),
      value=int(modulus, 16)
    )


def find_prime(primes: Iterable[Prime], min_size: int, preferred_size: int, max_size: int):
  best_candidate: Optional[Prime] = None

  for prime in primes:
    if (prime.size < min_size) or (prime.size > max_size) or (prime.type != 'safe') or (not prime.test_sieve):
      continue

    if (prime.size == preferred_size - 1) or (prime.size == preferred_size):
      return prime

    if (best_candidate is None) or (abs(prime.size - preferred_size) < abs(best_candidate.size - preferred_size)):
      best_candidate = prime

  return best_candidate
