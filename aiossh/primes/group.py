import functools
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass
class Group:
  generator: int
  prime: int

  @functools.cached_property
  def size(self):
    return self.prime.bit_length()


def select_group(groups: Iterable[Group], min_size: int, preferred_size: int, max_size: int):
  suitable_groups = [group for group in groups if (group.size >= min_size) and (group.size <= max_size)]

  if not suitable_groups:
    return None

  return min(
    suitable_groups,
    key=(lambda group: (
      # Groups with group.size > preferred_size are favored because the
      # condition is zero and thus minimized
      group.size <= preferred_size,
      abs(group.size - preferred_size),
    ))
  )
