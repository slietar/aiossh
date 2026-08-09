import dataclasses
import termios
from typing import Optional

from siossh.terminal_modes import TerminalModes


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
FLAG_FIELDS: dict[str, tuple[int, Optional[int]]] = {
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
  'imaxbel': (IFLAG, getattr(termios, 'IMAXBEL')),
  'iutf8': (IFLAG, getattr(termios, 'IUTF8')),

  'isig': (LFLAG, termios.ISIG),
  'icanon': (LFLAG, termios.ICANON),
  'echo': (LFLAG, termios.ECHO),
  'echoe': (LFLAG, termios.ECHOE),
  'echok': (LFLAG, termios.ECHOK),
  'echonl': (LFLAG, termios.ECHONL),
  'noflsh': (LFLAG, termios.NOFLSH),
  'tostop': (LFLAG, termios.TOSTOP),
  'iexten': (LFLAG, termios.IEXTEN),
  'echoctl': (LFLAG, getattr(termios, 'ECHOCTL')),
  'echoke': (LFLAG, getattr(termios, 'ECHOKE')),
  'pendin': (LFLAG, getattr(termios, 'PENDIN')),
  'xcase': (LFLAG, getattr(termios, 'XCASE', None)),

  'opost': (OFLAG, termios.OPOST),
  'onlcr': (OFLAG, termios.ONLCR),
  'ocrnl': (OFLAG, getattr(termios, 'OCRNL')),
  'onocr': (OFLAG, getattr(termios, 'ONOCR')),
  'onlret': (OFLAG, getattr(termios, 'ONLRET')),
  'olcuc': (OFLAG, getattr(termios, 'OLCUC', None)),

  'parenb': (CFLAG, termios.PARENB),
  'parodd': (CFLAG, termios.PARODD),
}

# Character-size fields -> CSIZE bit pattern (CSIZE is a 2-bit mask, not an
# independent flag, so cs7/cs8 can't share the generic FLAG_FIELDS bit logic)
CSIZE_FIELDS = {
  'cs7': termios.CS7,
  'cs8': termios.CS8,
}

SPEED_FIELDS = {
  'tty_op_ispeed': ISPEED,
  'tty_op_ospeed': OSPEED,
}


def apply_terminal_modes(fd: int, modes: TerminalModes):
  attrs = termios.tcgetattr(fd)
  cc = list(attrs[CC])

  for name, value in dataclasses.asdict(modes).items():
    if value is None:
      continue

    if name in CC_FIELDS:
      cc[CC_FIELDS[name]] = bytes([value & 0xFF])

    elif name in FLAG_FIELDS:
      which, bit = FLAG_FIELDS[name]

      if bit is not None:
        if value != 0:
          attrs[which] |= bit
        else:
          attrs[which] &= ~bit

    elif name in CSIZE_FIELDS:
      if value != 0:
        attrs[CFLAG] = (attrs[CFLAG] & ~termios.CSIZE) | CSIZE_FIELDS[name]

    elif name in SPEED_FIELDS:
      speed = baud_to_termios_constant(value)

      if speed is not None:
        attrs[SPEED_FIELDS[name]] = speed

  attrs[CC] = cc
  termios.tcsetattr(fd, termios.TCSANOW, attrs)


def baud_to_termios_constant(baud: int):
  table = {
    50: termios.B50,
    75: termios.B75,
    110: termios.B110,
    134: termios.B134,
    150: termios.B150,
    200: termios.B200,
    300: termios.B300,
    600: termios.B600,
    1200: termios.B1200,
    1800: termios.B1800,
    2400: termios.B2400,
    4800: termios.B4800,
    9600: termios.B9600,
    19200: termios.B19200,
    38400: termios.B38400,
    57600: termios.B57600,
    115200: termios.B115200,
    230400: termios.B230400,
  }

  return table.get(baud)
