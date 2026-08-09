from collections.abc import Collection
from dataclasses import dataclass
from typing import Annotated, ClassVar, Literal, Optional, override

from ..encoding import (
  AutoCodable,
  CodableABC,
  Name,
  NameList,
  UnionAnnotation,
)
from ..structures.primitives import (
  decode_boolean,
  decode_name,
  decode_string,
  decode_text,
  encode_boolean,
  encode_name,
  encode_string,
  encode_text,
)
from .base import AutoCodableMessage
from .types import LanguageTag


# See: RFC 4252

type AuthenticationMethodName = Literal['password', 'publickey', 'hostbased', 'none']

AUTHENTICATION_METHOD_NAMES: Collection[AuthenticationMethodName] = ['password', 'publickey', 'hostbased', 'none']


@dataclass(slots=True)
class UserAuthRequestMessage(AutoCodableMessage):
  id: ClassVar[int] = 50

  user_name: str
  service_name: str
  type: str
  details: Annotated[
    UserAuthRequestDetailsHostBased | UserAuthRequestDetailsNone | UserAuthRequestDetailsPublicKey | UserAuthRequestDetailsPassword,
    UnionAnnotation('type', 'key'),
  ]


@dataclass(kw_only=True, slots=True)
class UserAuthRequestDetailsHostBased(AutoCodable):
  key: ClassVar[str] = 'hostbased'

  public_key_algorithm: Name
  public_host_key: bytes
  client_host_name: str
  signature: bytes

@dataclass(kw_only=True, slots=True)
class UserAuthRequestDetailsNone(AutoCodable):
  key: ClassVar[str] = 'none'

@dataclass(kw_only=True, slots=True)
class UserAuthRequestDetailsPublicKey(CodableABC):
  key: ClassVar[str] = 'publickey'

  algorithm: Name
  public_key: bytes
  signature: Optional[bytes]

  @override
  def encode(self):
    return (
      encode_boolean(self.signature is not None)
      + encode_name(self.algorithm)
      + encode_string(self.public_key)
      + (encode_string(self.signature) if self.signature is not None else b'')
    )

  @override
  @classmethod
  def decode(cls, reader):
    contains_signature = decode_boolean(reader)

    return cls(
      algorithm=decode_name(reader),
      public_key=decode_string(reader),
      signature=(decode_string(reader) if contains_signature else None),
    )

@dataclass(kw_only=True, slots=True)
class UserAuthRequestDetailsPassword(CodableABC):
  key: ClassVar[str] = 'password'

  password: str
  new_password: Optional[str] = None

  @override
  def encode(self):
    return (
      encode_boolean(self.new_password is not None)
      + encode_text(self.password)
      + (encode_text(self.new_password) if self.new_password is not None else b'')
    )

  @override
  @classmethod
  def decode(cls, reader):
    contains_new_password = decode_boolean(reader)

    return cls(
      password=decode_text(reader),
      new_password=(decode_text(reader) if contains_new_password else None),
    )



@dataclass(kw_only=True, slots=True)
class UserAuthFailureMessage(AutoCodableMessage):
  id: ClassVar[int] = 51

  supported_methods: NameList
  partial_success: bool = False

@dataclass(kw_only=True, slots=True)
class UserAuthSuccessMessage(AutoCodableMessage):
  id: ClassVar[int] = 52

@dataclass(kw_only=True, slots=True)
class UserAuthBannerMessage(AutoCodableMessage):
  id: ClassVar[int] = 53

  message: str
  language_tag: LanguageTag

@dataclass(kw_only=True, slots=True)
class UserAuthPasswordChangeRequestMessage(AutoCodableMessage):
  id: ClassVar[int] = 60

  prompt: str
  language_tag: LanguageTag

@dataclass(kw_only=True, slots=True)
class UserAuthPublicKeyOk(AutoCodableMessage):
  id: ClassVar[int] = 60

  algorithm: str
  public_key: bytes
