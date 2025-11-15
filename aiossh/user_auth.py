import logging
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.hashes import SHA1

from .error import ProtocolError, UnreachableError
from .flow import MessageFlowRead
from .messages.user_auth import (
  AUTHENTICATION_METHOD_NAMES,
  UserAuthFailureMessage,
  UserAuthPasswordChangeRequestMessage,
  UserAuthPublicKeyOk,
  UserAuthRequestMessage,
  UserAuthRequestNoneMessage,
  UserAuthRequestPasswordMessage,
  UserAuthRequestPublicKeyMessage,
  UserAuthSuccessMessage,
)
from .structures.keys import (
  decode_ed25519_public_key,
  decode_ed25519_signature,
  decode_rsa_public_key,
  decode_rsa_signature,
)
from .structures.primitives import encode_string
from .util import ReadableBytesIOImpl


if TYPE_CHECKING:
  from .connection import Connection


logger = logging.getLogger(__name__)


# TODO: Implement "keyboard-interactive" authentication method (RFC 4256), which is not stateless
# TODO: Implement "gssapi-with-mic" authentication method (RFC 4462)
# TODO: Implement banner message


# See: RFC 4252

async def run_user_auth(conn: Connection, read: MessageFlowRead) -> bool:
  request_message, _ = await read(UserAuthRequestMessage)
  supported_methods = await conn.client.get_auth_methods(request_message.user_name)
  assert supported_methods.issubset(AUTHENTICATION_METHOD_NAMES)

  match request_message:
    case UserAuthRequestNoneMessage():
      if 'none' in supported_methods:
        conn.write_message(UserAuthSuccessMessage())
        return True
      else:
        conn.write_message(UserAuthFailureMessage(supported_methods=list(supported_methods)))
        return False

    case UserAuthRequestPasswordMessage():
      conn.write_message(UserAuthPasswordChangeRequestMessage(prompt='Please change your password', language_tag='en'))
      return False

    case UserAuthRequestPublicKeyMessage():
      # RSA requires "-o PubkeyAcceptedKeyTypes=ssh-rsa" in the OpenSSH client

      match request_message.algorithm:
        case 'ssh-ed25519':
          with ReadableBytesIOImpl(request_message.public_key) as reader:
            key = decode_ed25519_public_key(reader)
        case 'ssh-rsa':
          with ReadableBytesIOImpl(request_message.public_key) as reader:
            key = decode_rsa_public_key(reader)
        case _:
          conn.write_message(UserAuthFailureMessage(supported_methods=list(supported_methods)))
          return False

      if request_message.signature is not None:
        assert conn.session_id is not None
        signed_data = encode_string(conn.session_id) + request_message.encode_signed()

        match request_message.algorithm:
          case 'ssh-ed25519':
            assert isinstance(key, Ed25519PublicKey)

            with ReadableBytesIOImpl(request_message.signature) as reader:
              signature = decode_ed25519_signature(reader)

            try:
              key.verify(signature, signed_data)
            except InvalidSignature:
              logger.debug('Invalid signature')
              conn.write_message(UserAuthFailureMessage(supported_methods=list(supported_methods)))
              return False

          case 'ssh-rsa':
            assert isinstance(key, RSAPublicKey)

            with ReadableBytesIOImpl(request_message.signature) as reader:
              signature = decode_rsa_signature(reader)

            try:
              key.verify(
                signature,
                signed_data,
                PKCS1v15(),
                SHA1(),
              )
            except InvalidSignature:
              logger.debug('Invalid signature')
              conn.write_message(UserAuthFailureMessage(supported_methods=list(supported_methods)))
              return False

          case _:
            raise UnreachableError

      if not await conn.client.auth_with_public_key(
        user_name=request_message.user_name,
        key=key,
        in_use=(request_message.signature is not None),
      ):
        conn.write_message(UserAuthFailureMessage(supported_methods=list(supported_methods)))
        return False

      if request_message.signature is None:
        conn.write_message(UserAuthPublicKeyOk(
          algorithm=request_message.algorithm,
          public_key=request_message.public_key,
        ))

        return False
      else:
        conn.write_message(UserAuthSuccessMessage())
        return True

    case _:
      raise ProtocolError
