from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA1

from .error import ProtocolError
from .flow import MessageFlowRead
from .messages.user_auth import (
  AuthenticationMethodName,
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


# TODO: Implement "keyboard-interactive" authentication method (RFC 4256), which is not stateless
# TODO: Implement "gssapi-with-mic" authentication method (RFC 4462)
# TODO: Implement banner message


async def run_user_auth(conn: Connection, read: MessageFlowRead):
  request_message, _ = await read(UserAuthRequestMessage)
  supported_methods: list[AuthenticationMethodName] = ['none', 'publickey']

  match request_message:
    case UserAuthRequestNoneMessage():
      if 'none' in supported_methods:
        conn.write_message(UserAuthSuccessMessage())
      else:
        conn.write_message(UserAuthFailureMessage(supported_methods=supported_methods))

    case UserAuthRequestPasswordMessage():
      conn.write_message(UserAuthPasswordChangeRequestMessage(prompt='Please change your password', language_tag='en'))

    case UserAuthRequestPublicKeyMessage():
      supported_algorithms = ['ssh-ed25519', 'ssh-rsa']

      if request_message.signature is None:
        if request_message.algorithm in supported_algorithms:
          conn.write_message(UserAuthPublicKeyOk(
            algorithm=request_message.algorithm,
            public_key=request_message.public_key,
          ))
        else:
          conn.write_message(UserAuthFailureMessage(supported_methods=supported_methods))
      else:
        assert conn.session_id is not None
        signed_data = encode_string(conn.session_id) + request_message.encode_signed()

        match request_message.algorithm:
          case 'ssh-ed25519':
            with ReadableBytesIOImpl(request_message.public_key) as reader:
              key = decode_ed25519_public_key(reader)

            with ReadableBytesIOImpl(request_message.signature) as reader:
              signature = decode_ed25519_signature(reader)

            try:
              key.verify(signature, signed_data)
            except InvalidSignature as e:
              raise ProtocolError from e

            conn.write_message(UserAuthSuccessMessage())

          # Requires "-o PubkeyAcceptedKeyTypes=ssh-rsa" in the OpenSSH client
          case 'ssh-rsa':
            with ReadableBytesIOImpl(request_message.public_key) as reader:
              key = decode_rsa_public_key(reader)

            with ReadableBytesIOImpl(request_message.signature) as reader:
              signature = decode_rsa_signature(reader)

            try:
              key.verify(
                signature,
                signed_data,
                PKCS1v15(),
                SHA1(),
              )
            except InvalidSignature as e:
              raise ProtocolError from e

            conn.write_message(UserAuthSuccessMessage())

          case _:
            conn.write_message(UserAuthFailureMessage(supported_methods=supported_methods))
