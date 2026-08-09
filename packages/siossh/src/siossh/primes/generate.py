from cryptography.hazmat.primitives.asymmetric import dh

from .group import Group


def generate_group(size: int, *, generator: int = 2):
  param_numbers = dh.generate_parameters(generator=generator, key_size=size).parameter_numbers()

  return Group(
    generator=param_numbers.g,
    prime=param_numbers.p,
  )
