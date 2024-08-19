from abc import ABC
import struct
from dataclasses import KW_ONLY, dataclass
from typing import ClassVar, Optional

from ..error import ProtocolError
from ..structures.primitives import (decode_boolean, decode_name,
                                     decode_string, decode_text,
                                     encode_boolean, encode_name,
                                     encode_name_list, encode_string,
                                     encode_text)
from .base import DecodableMessage, EncodableMessage
from .types import LanguageTag


# See: RFC 4252

@dataclass(slots=True)
class UserAuthRequestMessage(DecodableMessage, ABC):
  id: ClassVar[int] = 50

  service_name: str
  user_name: str

  @classmethod
  def decode(cls, reader):
    user_name = decode_text(reader)
    service_name = decode_text(reader)
    auth_method = decode_name(reader)

    match auth_method:
      case 'hostbased':
        return UserAuthRequestHostBasedMessage(
          user_name=user_name,
          service_name=service_name,

          # Order matters
          public_key_algorithm=decode_name(reader),
          public_host_key=decode_string(reader),
          client_host_name=decode_text(reader),
          signature=decode_string(reader)
        )

      case 'none':
        return UserAuthRequestNoneMessage(
          service_name=service_name,
          user_name=user_name
        )

      case 'password':
        contains_new_password = decode_boolean(reader)

        return UserAuthRequestPasswordMessage(
          service_name=service_name,
          user_name=user_name,

          # Order matters
          password=decode_text(reader),
          new_password=(decode_text(reader) if contains_new_password else None)
        )

      case 'publickey':
        contains_signature = decode_boolean(reader)

        return UserAuthRequestPublicKeyMessage(
          service_name=service_name,
          user_name=user_name,

          # Order matters
          algorithm=decode_name(reader),
          public_key=decode_string(reader),
          signature=(decode_string(reader) if contains_signature else None)
        )

      case _:
        raise ProtocolError(f'Unknown authentication method {auth_method!r}')


@dataclass(kw_only=True, slots=True)
class UserAuthRequestHostBasedMessage(UserAuthRequestMessage):
  client_host_name: str
  public_host_key: bytes
  public_key_algorithm: str
  signature: bytes

@dataclass(slots=True)
class UserAuthRequestNoneMessage(UserAuthRequestMessage):
  pass

@dataclass(kw_only=True, slots=True)
class UserAuthRequestPublicKeyMessage(UserAuthRequestMessage):
  algorithm: str
  public_key: bytes
  signature: Optional[bytes]

  def encode_signed(self):
    return bytes([self.id])\
      + encode_text(self.user_name)\
      + encode_text(self.service_name)\
      + encode_name('publickey')\
      + encode_boolean(True)\
      + encode_name(self.algorithm)\
      + encode_string(self.public_key)

@dataclass(slots=True)
class UserAuthRequestPasswordMessage(UserAuthRequestMessage):
  password: str
  new_password: Optional[str] = None


@dataclass(kw_only=True, slots=True)
class UserAuthFailureMessage(EncodableMessage):
  id: ClassVar[int] = 51

  partial_success: bool = False
  supported_methods: list[str]

  def encode(self):
    return encode_name_list(self.supported_methods) + struct.pack('?', self.partial_success)

@dataclass(kw_only=True, slots=True)
class UserAuthSuccessMessage(EncodableMessage):
  id: ClassVar[int] = 52

  def encode(self):
    return b''

@dataclass(slots=True)
class UserAuthBannerMessage(EncodableMessage):
  id: ClassVar[int] = 53

  message: str
  _: KW_ONLY
  language_tag: LanguageTag

  def encode(self):
    return encode_string(self.message.encode()) + encode_name(self.language_tag)

@dataclass(slots=True)
class UserAuthPasswordChangeRequestMessage(EncodableMessage):
  id: ClassVar[int] = 60

  prompt: str
  _: KW_ONLY
  language_tag: LanguageTag

  def encode(self):
    return encode_string(self.prompt.encode()) + encode_name(self.language_tag)

@dataclass(kw_only=True, slots=True)
class UserAuthPublicKeyOk(EncodableMessage):
  id: ClassVar[int] = 60

  algorithm: str
  public_key: bytes

  def encode(self):
    return encode_name(self.algorithm) + encode_string(self.public_key)
