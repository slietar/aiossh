from dataclasses import dataclass
import struct
from typing import ClassVar, Optional

from ..error import ProtocolError
from ..structures.primitives import decode_boolean, decode_string, encode_string, encore_name_list
from .base import DecodableMessage, EncodableMessage


# See: RFC 4252

@dataclass(kw_only=True, slots=True)
class UserAuthRequestMessage(DecodableMessage):
  id: ClassVar[int] = 50

  service_name: str
  user_name: str

  @classmethod
  def decode(cls, reader):
    user_name_raw = decode_string(reader)

    try:
      user_name = user_name_raw.decode()
    except UnicodeDecodeError as e:
      raise ProtocolError from e

    service_name_raw = decode_string(reader)

    try:
      service_name = service_name_raw.decode('ascii')
    except UnicodeDecodeError as e:
      raise ProtocolError from e

    auth_method = decode_string(reader)

    match auth_method:
      case b'none':
        return UserAuthRequestNoneMessage(
          service_name=service_name,
          user_name=user_name
        )

      case b'publickey':
        contains_signature = decode_boolean(reader)
        public_key_algorithm = decode_string(reader)
        public_key_blob = decode_string(reader)

        signature = decode_string(reader) if contains_signature else None

        return UserAuthRequestUserMessage(
          public_key_algorithm=public_key_algorithm,
          public_key_blob=public_key_blob,
          signature=signature,
          service_name=service_name,
          user_name=user_name
        )

      case b'password':
        contains_new_password = decode_boolean(reader)
        raw_password = decode_string(reader)

        try:
          password = raw_password.decode()
        except UnicodeDecodeError as e:
          raise ProtocolError from e

        if contains_new_password:
          raw_new_password = decode_string(reader)

          try:
            new_password = raw_new_password.decode()
          except UnicodeDecodeError as e:
            raise ProtocolError from e
        else:
          new_password = None

        return UserAuthRequestPasswordMessage(
          password=password,
          new_password=new_password,
          service_name=service_name,
          user_name=user_name
        )

      case b'hostbased':
        raise ProtocolError('Hostbased authentication is not supported')
      case _:
        raise ProtocolError(f'Unknown authentication method {auth_method!r}')


@dataclass(kw_only=True, slots=True)
class UserAuthRequestNoneMessage(UserAuthRequestMessage):
  pass

@dataclass(kw_only=True, slots=True)
class UserAuthRequestUserMessage(UserAuthRequestMessage):
  public_key_algorithm: bytes
  public_key_blob: bytes
  signature: Optional[bytes]

@dataclass(kw_only=True, slots=True)
class UserAuthRequestPasswordMessage(UserAuthRequestMessage):
  password: str
  new_password: Optional[str]


@dataclass(kw_only=True, slots=True)
class UserAuthFailureMessage(EncodableMessage):
  id: ClassVar[int] = 51

  partial_success: bool = False
  supported_methods: list[str]

  def encode(self):
    return encore_name_list(self.supported_methods) + struct.pack('?', self.partial_success)

@dataclass(kw_only=True, slots=True)
class UserAuthSuccessMessage(EncodableMessage):
  id: ClassVar[int] = 52

  def encode(self):
    return b''

@dataclass(kw_only=True, slots=True)
class UserAuthBannerMessage(EncodableMessage):
  id: ClassVar[int] = 53

  message: str
  language_tag: str

  def encode(self):
    return encode_string(self.message.encode()) + encode_string(self.language_tag.encode('ascii'))

@dataclass(kw_only=True, slots=True)
class UserAuthPasswordChangeRequestMessage(EncodableMessage):
  id: ClassVar[int] = 60

  prompt: str
  language_tag: str

  def encode(self):
    return encode_string(self.prompt.encode()) + encode_string(self.language_tag.encode('ascii'))
