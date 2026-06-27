from collections.abc import Collection
from dataclasses import dataclass
from typing import Annotated, ClassVar, Literal, Optional

from ..encoding import AutoCodable, Name, UnionAnnotation
from ..structures.primitives import (
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
class UserAuthRequestDetailsPublicKey(AutoCodable):
  key: ClassVar[str] = 'publickey'

  contains_signature: bool
  algorithm: Name
  public_key: bytes
  signature: Optional[bytes]

  def encode_signed(self):
    return (
      bytes([self.id])
      + encode_text(self.user_name)
      + encode_text(self.service_name)
      + encode_name('publickey')
      + encode_boolean(True)
      + encode_name(self.algorithm)
      + encode_string(self.public_key)
    )

@dataclass(kw_only=True, slots=True)
class UserAuthRequestDetailsPassword(AutoCodable):
  key: ClassVar[str] = 'password'

  contains_new_password: bool
  password: str
  new_password: Optional[str] = None


@dataclass(kw_only=True, slots=True)
class UserAuthFailureMessage(AutoCodableMessage):
  id: ClassVar[int] = 51

  supported_methods: list[str]
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
