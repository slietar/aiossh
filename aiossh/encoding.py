import builtins
import dataclasses
import typing
from dataclasses import dataclass
from typing import Annotated, Any, ClassVar, Literal, get_type_hints

from .structures.primitives import (decode_boolean, decode_mpint, decode_name,
                                     decode_string, decode_text, decode_uint32,
                                     encode_boolean, encode_mpint, encode_name,
                                     encode_string, encode_text, encode_uint32)
from .util import ReadableBytesIOImpl


type Encoding = Literal['boolean', 'mpint', 'name', 'string', 'text', 'uint32']

@dataclass(slots=True)
class EncodingAnnotation:
  name: Encoding


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
        if isinstance(annotation, EncodingAnnotation):
          found = True
          encodings[field.name] = annotation.name
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
        print(type(field_type))
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

    return cls(**field_values)


if __name__ == '__main__':
  @dataclass(kw_only=True, slots=True)
  class User(Codable):
    id: ClassVar[int] = 12

    age: Mpint
    name: Annotated[str, EncodingAnnotation('name')]

  @dataclass(slots=True)
  class AdminUser(User):
    senior: bool


  u = AdminUser(age=550729374570437490275934, name='John', senior=True)
  encoded = u.encode()

  print(encoded.hex(' '))

  with ReadableBytesIOImpl(encoded) as reader:
    print(AdminUser.decode(reader))
