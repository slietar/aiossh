import termios
from dataclasses import dataclass
from typing import Optional, override

from .encoding import CodableABC
from .error import ProtocolError
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

  # See: RFC 8160
  iutf8: Optional[bool] = None

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

          case 42:
            if value not in (0, 1):
              raise ProtocolError

            modes.iutf8 = bool(value)

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


# --- Field -> (attr index, cc index) tables -------------------------------
# termios array layout: [iflag, oflag, cflag, lflag, ispeed, ospeed, cc]
IFLAG, OFLAG, CFLAG, LFLAG, ISPEED, OSPEED, CC = range(7)

# Control character fields -> termios.VXXX index into the cc array
# (vdsusp, vflush, vswtch, vstatus have no POSIX equivalent on Linux)
CC_FIELDS = {
  'vintr': termios.VINTR,
  'vquit': termios.VQUIT,
  'verase': termios.VERASE,
  'vkill': termios.VKILL,
  'veof': termios.VEOF,
  'veol': termios.VEOL,
  'veol2': termios.VEOL2,
  'vstart': termios.VSTART,
  'vstop': termios.VSTOP,
  'vsusp': termios.VSUSP,
  'vreprint': termios.VREPRINT,
  'vwerase': termios.VWERASE,
  'vlnext': termios.VLNEXT,
  'vdiscard': termios.VDISCARD,
}

# Flag fields -> (which flag word, the bit constant)
FLAG_FIELDS = {
  'ignpar': (IFLAG, termios.IGNPAR),
  'parmrk': (IFLAG, termios.PARMRK),
  'inpck': (IFLAG, termios.INPCK),
  'istrip': (IFLAG, termios.ISTRIP),
  'inlcr': (IFLAG, termios.INLCR),
  'igncr': (IFLAG, termios.IGNCR),
  'icrnl': (IFLAG, termios.ICRNL),
  'ixon': (IFLAG, termios.IXON),
  'ixany': (IFLAG, termios.IXANY),
  'ixoff': (IFLAG, termios.IXOFF),
  'iutf8': (IFLAG, getattr(termios, 'IUTF8', 0)),

  'isig': (LFLAG, termios.ISIG),
  'icanon': (LFLAG, termios.ICANON),
  'echo': (LFLAG, termios.ECHO),
  'echoe': (LFLAG, termios.ECHOE),
  'echok': (LFLAG, termios.ECHOK),
  'echonl': (LFLAG, termios.ECHONL),
  'noflsh': (LFLAG, termios.NOFLSH),
  'tostop': (LFLAG, termios.TOSTOP),
  'iexten': (LFLAG, termios.IEXTEN),
  'echoctl': (LFLAG, getattr(termios, 'ECHOCTL', 0)),
  'echoke': (LFLAG, getattr(termios, 'ECHOKE', 0)),
  'pendin': (LFLAG, getattr(termios, 'PENDIN', 0)),

  'opost': (OFLAG, termios.OPOST),
  'onlcr': (OFLAG, termios.ONLCR),
  'ocrnl': (OFLAG, getattr(termios, 'OCRNL', 0)),
  'onocr': (OFLAG, getattr(termios, 'ONOCR', 0)),
  'onlret': (OFLAG, getattr(termios, 'ONLRET', 0)),

  'parenb': (CFLAG, termios.PARENB),
  'parodd': (CFLAG, termios.PARODD),
}

SPEED_FIELDS = {'tty_op_ispeed': ISPEED, 'tty_op_ospeed': OSPEED}


def apply_terminal_modes(fd, modes: TerminalModes):
  attrs = termios.tcgetattr(fd)
  cc = list(attrs[CC])

  for name, value in vars(modes).items():
    if value is None:
      continue

    if name in CC_FIELDS:
      cc[CC_FIELDS[name]] = bytes([value & 0xFF])
    elif name in FLAG_FIELDS:
      which, bit = FLAG_FIELDS[name]
      if bit == 0:
        continue
      if value:
        attrs[which] |= bit
      else:
        attrs[which] &= ~bit
    elif name in SPEED_FIELDS:
      attrs[SPEED_FIELDS[name]] = baud_to_termios_constant(value)

  attrs[CC] = cc
  termios.tcsetattr(fd, termios.TCSANOW, attrs)
  print(f'Applied terminal modes: {attrs} to fd {fd}')


def baud_to_termios_constant(baud: int) -> int:
  table = {
    50: termios.B50, 75: termios.B75, 110: termios.B110,
    134: termios.B134, 150: termios.B150, 200: termios.B200,
    300: termios.B300, 600: termios.B600, 1200: termios.B1200,
    1800: termios.B1800, 2400: termios.B2400, 4800: termios.B4800,
    9600: termios.B9600, 19200: termios.B19200, 38400: termios.B38400,
    57600: termios.B57600, 115200: termios.B115200,
    230400: termios.B230400,
  }
  return table.get(baud, termios.B38400)  # fallback default
