from dataclasses import dataclass
from typing import Optional, override

from .encoding import CodableABC
from .structures.primitives import decode_uint32


# See: RFC 4254 Section 8

@dataclass(kw_only=True, slots=True)
class TerminalModes(CodableABC):
  vintr: Optional[int] = None
  vquit: Optional[int] = None
  verase: Optional[int] = None
  vkill: Optional[int] = None
  veof: Optional[int] = None
  veol: Optional[int] = None
  veol2: Optional[int] = None
  vstart: Optional[int] = None
  vstop: Optional[int] = None
  vsusp: Optional[int] = None
  vdsusp: Optional[int] = None
  vreprint: Optional[int] = None
  vwerase: Optional[int] = None
  vlnext: Optional[int] = None
  vflush: Optional[int] = None
  vswtch: Optional[int] = None
  vstatus: Optional[int] = None
  vdiscard: Optional[int] = None

  ignpar: Optional[int] = None
  parmrk: Optional[int] = None
  inpck: Optional[int] = None
  istrip: Optional[int] = None
  inlcr: Optional[int] = None
  igncr: Optional[int] = None
  icrnl: Optional[int] = None
  iuclc: Optional[int] = None
  ixon: Optional[int] = None
  ixany: Optional[int] = None
  ixoff: Optional[int] = None
  imaxbel: Optional[int] = None

  isig: Optional[int] = None
  icanon: Optional[int] = None
  xcase: Optional[int] = None
  echo: Optional[int] = None
  echoe: Optional[int] = None
  echok: Optional[int] = None
  echonl: Optional[int] = None
  noflsh: Optional[int] = None
  tostop: Optional[int] = None
  iexten: Optional[int] = None
  echoctl: Optional[int] = None
  echoke: Optional[int] = None
  pendin: Optional[int] = None

  opost: Optional[int] = None
  olcuc: Optional[int] = None
  onlcr: Optional[int] = None
  ocrnl: Optional[int] = None
  onocr: Optional[int] = None
  onlret: Optional[int] = None

  cs7: Optional[int] = None
  cs8: Optional[int] = None
  parenb: Optional[int] = None
  parodd: Optional[int] = None

  tty_op_ospeed: Optional[int] = None
  tty_op_ispeed: Optional[int] = None

  @override
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
          case 11:
            modes.vdsusp = value
          case 12:
            modes.vreprint = value
          case 13:
            modes.vwerase = value
          case 14:
            modes.vlnext = value
          case 15:
            modes.vflush = value
          case 16:
            modes.vswtch = value
          case 17:
            modes.vstatus = value
          case 18:
            modes.vdiscard = value

          case 30:
            modes.ignpar = value
          case 31:
            modes.parmrk = value
          case 32:
            modes.inpck = value
          case 33:
            modes.istrip = value
          case 34:
            modes.inlcr = value
          case 35:
            modes.igncr = value
          case 36:
            modes.icrnl = value
          case 37:
            modes.iuclc = value
          case 38:
            modes.ixon = value
          case 39:
            modes.ixany = value
          case 40:
            modes.ixoff = value
          case 41:
            modes.imaxbel = value

          case 50:
            modes.isig = value
          case 51:
            modes.icanon = value
          case 52:
            modes.xcase = value
          case 53:
            modes.echo = value
          case 54:
            modes.echoe = value
          case 55:
            modes.echok = value
          case 56:
            modes.echonl = value
          case 57:
            modes.noflsh = value
          case 58:
            modes.tostop = value
          case 59:
            modes.iexten = value
          case 60:
            modes.echoctl = value
          case 61:
            modes.echoke = value
          case 62:
            modes.pendin = value

          case 70:
            modes.opost = value
          case 71:
            modes.olcuc = value
          case 72:
            modes.onlcr = value
          case 73:
            modes.ocrnl = value
          case 74:
            modes.onocr = value
          case 75:
            modes.onlret = value

          case 90:
            modes.cs7 = value
          case 91:
            modes.cs8 = value
          case 92:
            modes.parenb = value
          case 93:
            modes.parodd = value

          case 128:
            modes.tty_op_ispeed = value
          case 129:
            modes.tty_op_ospeed = value

          case _:
            print('Unsupported opcode', opcode)
            reader.read_all()
            break
      else:
        reader.read_all()
        break

    return modes
