import builtins
from dataclasses import dataclass
from typing import Optional, override

from .encoding import CodableABC
from .structures.primitives import decode_uint32


# See: RFC 4254 Section 8

@dataclass(kw_only=True, slots=True)
class TerminalModes(CodableABC):
  vintr: int = 0xff
  vquit: int = 0xff
  verase: int = 0xff
  vkill: int = 0xff
  veof: int = 0xff
  veol: int = 0xff
  veol2: int = 0xff
  vstart: int = 0xff
  vstop: int = 0xff
  vsusp: int = 0xff

  tty_op_ospeed: Optional[int] = None
  tty_op_ispeed: Optional[int] = None

  def encode(self):
    return b'\x00'

  @classmethod
  @override
  def decode(cls, reader):
    modes = cls()

    while True:
      opcode = reader.read(1)[0]

      if opcode == 0:
        break

      if opcode < 160:
        value = decode_uint32(reader)

        match opcode:
          case 1:
            modes.vintr = value
          case 2:
            modes.vquit = value
          case 3:
            modes.verase = value
          case 4:
            modes.vkill = value
          case 5:
            modes.veof = value
          case 6:
            modes.veol = value
          case 7:
            modes.veol2 = value
          case 8:
            modes.vstart = value
          case 9:
            modes.vstop = value
          case 10:
            modes.vsusp = value
          case 128:
            modes.tty_op_ispeed = value
          case 129:
            modes.tty_op_ospeed = value
          case _:
            print(opcode)
            reader.read_all()
            break
      else:
        reader.read_all()
        break

    return modes
