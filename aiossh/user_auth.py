from typing import TYPE_CHECKING

from .error import ProtocolError
from .flow import MessageFlowRead
from .messages.user_auth import (UserAuthFailureMessage,
                                 UserAuthPasswordChangeRequestMessage,
                                 UserAuthPublicKeyOk, UserAuthRequestMessage,
                                 UserAuthRequestNoneMessage,
                                 UserAuthRequestPasswordMessage,
                                 UserAuthRequestPublicKeyMessage,
                                 UserAuthSuccessMessage)
from .structures.keys import (decode_ed25519_public_key,
                              decode_ed25519_signature)
from .structures.primitives import encode_string
from .util import ReadableBytesIOImpl

if TYPE_CHECKING:
  from .connection import Connection


async def run_user_auth(conn: 'Connection', read: MessageFlowRead):
  request_message, _ = await read(UserAuthRequestMessage)

  match request_message:
    case UserAuthRequestNoneMessage():
      conn.write_message(UserAuthFailureMessage(supported_methods=['publickey']))

    case UserAuthRequestPasswordMessage():
      conn.write_message(UserAuthPasswordChangeRequestMessage(prompt='Please change your password', language_tag='en'))

    case UserAuthRequestPublicKeyMessage():
      if request_message.signature is None:
        conn.write_message(UserAuthPublicKeyOk(
          algorithm=request_message.algorithm,
          public_key=request_message.public_key
        ))
      else:
        assert conn.session_id is not None
        signed_data = encode_string(conn.session_id) + request_message.encode_signed()

        match request_message.algorithm:
          case 'ssh-ed25519':
            from cryptography import exceptions

            with ReadableBytesIOImpl(request_message.public_key) as reader:
              key = decode_ed25519_public_key(reader)

            with ReadableBytesIOImpl(request_message.signature) as reader:
              signature = decode_ed25519_signature(reader)

            try:
              key.verify(signature, signed_data)
            except exceptions.InvalidSignature as e:
              raise ProtocolError from e

            conn.write_message(UserAuthSuccessMessage())

          case _:
            conn.write_message(UserAuthFailureMessage(supported_methods=['publickey']))
