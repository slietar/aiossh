import logging
from typing import TYPE_CHECKING

from .error import ProtocolError
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
from .public.resolve import resolve_public_key
from .reader import Reader
from .structures.primitives import encode_string


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
      # Using "ssh-rsa" requires "-o PubkeyAcceptedKeyTypes=ssh-rsa" in the OpenSSH client

      public_key_type = resolve_public_key(request_message.algorithm)

      if public_key_type is None:
        conn.write_message(UserAuthFailureMessage(supported_methods=list(supported_methods)))
        return False

      with Reader(request_message.public_key) as reader:
        key = public_key_type.decode(reader)

      if request_message.signature is not None:
        assert conn.session_id is not None
        signed_data = encode_string(conn.session_id) + request_message.encode_signed()

        if not key.decode_verify(request_message.algorithm, request_message.signature, signed_data):
          logger.debug('Invalid signature')
          conn.write_message(UserAuthFailureMessage(supported_methods=list(supported_methods)))
          return False

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
