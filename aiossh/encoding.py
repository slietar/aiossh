import builtins
import dataclasses
from types import NoneType, UnionType
import typing
from dataclasses import dataclass
from typing import Annotated, Any, ClassVar, Literal, get_type_hints

from .structures.primitives import (decode_boolean, decode_mpint, decode_name,
                                     decode_string, decode_text, decode_uint32,
                                     encode_boolean, encode_mpint, encode_name,
                                     encode_string, encode_text, encode_uint32)
from .util import ReadableBytesIOImpl


@dataclass(slots=True)
class UnionEncoding:
  discriminant: str
  variants: 'dict[Any, type[Codable]]'

type Encoding = Literal['boolean', 'mpint', 'name', 'string', 'text', 'uint32'] | UnionEncoding


@dataclass(slots=True)
class EncodingAnnotation:
  name: Encoding

@dataclass(slots=True)
class UnionAnnotation:
  discriminant: str
  variant_attr: str

type Mpint = Annotated[int, EncodingAnnotation('mpint')]
type Name = Annotated[str, EncodingAnnotation('name')]


def get_class_encodings(cls):
  encodings = dict[str, Encoding]()
  field_types = get_type_hints(cls, include_extras=True)

  for field in dataclasses.fields(cls):
    field_type = field_types[field.name]
    current_type = field_type

    if isinstance(current_type, typing.TypeAliasType):
      current_type = current_type.__value__

    if typing.get_origin(current_type) is Annotated:
      found = False

      for annotation in current_type.__metadata__:
        match annotation:
          case EncodingAnnotation():
            encodings[field.name] = annotation.name

          case UnionAnnotation(discriminant, variant_attr) if typing.get_origin(current_type.__origin__) is UnionType:
            encodings[field.name] = UnionEncoding(discriminant, {
              getattr(variant, variant_attr): variant for variant in typing.get_args(current_type.__origin__) if variant is not NoneType
            })

          case _:
            continue

        found = True
        break
      else:
        current_type = current_type.__origin__

      if found:
        continue

    match current_type:
      case builtins.bool:
        encodings[field.name] = 'boolean'
      case builtins.bytes:
        encodings[field.name] = 'string'
      case builtins.int:
        encodings[field.name] = 'uint32'
      case builtins.str:
        encodings[field.name] = 'text'
      case _:
        raise TypeError(f'Unsupported type: {field_type!r}')

  return encodings


@dataclass(slots=True)
class Codable:
  def encode(self):
    output = b''

    for field_name, encoding in get_class_encodings(self.__class__).items():
      value = getattr(self, field_name)

      match encoding:
        case 'boolean':
          output += encode_boolean(value)
        case 'mpint':
          output += encode_mpint(value)
        case 'name':
          output += encode_name(value)
        case 'string':
          output += encode_string(value)
        case 'text':
          output += encode_text(value)
        case 'uint32':
          output += encode_uint32(value)
        case UnionEncoding(discriminant, variants):
          if not isinstance(value, expected_variant_type := variants[getattr(self, discriminant)]):
            raise TypeError(f'Expected {expected_variant_type!r}, got {type(value)!r}')

          output += value.encode()
        case _:
          raise TypeError(f'Unsupported encoding: {encoding!r}')

    return output

  @classmethod
  def decode(cls, reader):
    field_values = dict[str, Any]()

    for field_name, encoding in get_class_encodings(cls).items():
      match encoding:
        case 'boolean':
          field_values[field_name] = decode_boolean(reader)
        case 'mpint':
          field_values[field_name] = decode_mpint(reader)
        case 'string':
          field_values[field_name] = decode_string(reader)
        case 'name':
          field_values[field_name] = decode_name(reader)
        case 'text':
          field_values[field_name] = decode_text(reader)
        case 'uint32':
          field_values[field_name] = decode_uint32(reader)
        case UnionEncoding(discriminant, variants):
          variant = variants.get(field_values[discriminant])

          if variant is not None:
            field_values[field_name] = variant.decode(reader)
          else:
            field_values[field_name] = None
            reader.read_all()
        case _:
          raise TypeError(f'Unsupported encoding: {encoding!r}')

    return cls(**field_values)


if __name__ == '__main__':
  # @dataclass(kw_only=True, slots=True)
  # class User(Codable):
  #   id: ClassVar[int] = 12

  #   age: Mpint
  #   name: Annotated[str, EncodingAnnotation('name')]

  # @dataclass(slots=True)
  # class AdminUser(User):
  #   senior: bool


  # u = AdminUser(age=550729374570437490275934, name='John', senior=True)
  # encoded = u.encode()

  # print(encoded.hex(' '))

  # with ReadableBytesIOImpl(encoded) as reader:
  #   print(AdminUser.decode(reader))

  @dataclass
  class A1(Codable):
    key: ClassVar[str] = '1'
    x: int = 56

  @dataclass
  class A2(Codable):
    key: ClassVar[str] = '2'

  @dataclass
  class Entry(Codable):
    variant: str
    details: Annotated[A1 | None, UnionAnnotation('variant', 'key')]

  entry = Entry(variant='1', details=A1())
  encoded = entry.encode()

  print(encoded.hex(' '))
  print(repr(encoded))

  with ReadableBytesIOImpl(b'\x00\x00\x00\x012\x00') as reader:
    print(Entry.decode(reader))
