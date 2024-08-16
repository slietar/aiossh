from dataclasses import dataclass
from typing import Optional

from .error import ProtocolError
from .version import SSH_PROTOCOL_VERSION


# See: RFC 4253 Section 4.2

@dataclass(kw_only=True, slots=True)
class IdentString:
  comment: Optional[str]
  software_version: str

  def __bytes__(self):
    return self.encode()

  def encode(self):
    return f'SSH-{SSH_PROTOCOL_VERSION}-{self.software_version}{f' {self.comment}' if self.comment else ''}'.encode()

  @classmethod
  def decode(cls, data: bytes, /):
    segments = data.split(b' ', maxsplit=2)
    sub_segments = segments[0].split(b'-')

    if len(sub_segments) != 3:
      raise ProtocolError

    if sub_segments[0] != b'SSH':
      raise ProtocolError

    if not sub_segments[1] != SSH_PROTOCOL_VERSION:
      raise ProtocolError

    try:
      software_version = sub_segments[2].decode('ascii')
    except UnicodeDecodeError as e:
      raise ProtocolError from e

    if not software_version.isprintable():
      raise ProtocolError

    if len(segments) == 2:
      comments = segments[1]
    else:
      comments = None

    return IdentString(
      # Encoding of comments is not specified in the RFC, assuming ASCII
      comment=(comments.decode('ascii') if comments else None),
      software_version=software_version,
    )
