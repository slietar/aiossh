class AlgorithmNegotiationError(Exception):
  pass

class IntegrityVerificationError(Exception):
  pass

class ProtocolError(Exception):
  pass

class ProtocolVersionNotSupportedError(Exception):
  pass

class UnreachableError(Exception):
  pass


class ConnectionTerminatedError(Exception):
  pass
