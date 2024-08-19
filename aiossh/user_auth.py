from typing import TYPE_CHECKING

from .flow import MessageFlowRead
from .messages.user_auth import (UserAuthBannerMessage, UserAuthFailureMessage,
                                 UserAuthPasswordChangeRequestMessage,
                                 UserAuthRequestMessage,
                                 UserAuthRequestNoneMessage,
                                 UserAuthRequestPasswordMessage,
                                 UserAuthSuccessMessage)

if TYPE_CHECKING:
  from .connection import Connection


async def run_user_auth(conn: 'Connection', read: MessageFlowRead):
  request_message, _ = await read(UserAuthRequestMessage)

  match request_message:
    case UserAuthRequestNoneMessage():
      conn.write_message(UserAuthFailureMessage(supported_methods=['password']))

    case UserAuthRequestPasswordMessage():
      print(request_message)
      conn.write_message(UserAuthPasswordChangeRequestMessage(prompt='Please change your password', language_tag='en'))
