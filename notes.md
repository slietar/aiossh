# Aiossh

- Open channel: "session"
  - Request: "pty-req"
  - Request: "x11-req"
  - Request: "env"
  - Request: "window-change"
  - Request: "signal"
  - Request: "xon-xoff"
  - Request: "exit-status" (the other way)
  - Request: "exit-signal" (the other way)

  - Only one of these can succeed per channel
    - Request: "shell"
    - Request: "exec"
    - Request: "subsystem"
- Open channel: "x11"
- Open channel: "direct-tcpip"
- Open channel: "forwarded-tcpip"
- Global request: "tcpip-forward"
- Global request: "cancel-tcpip-forward"


## References

- [RFC 4250](https://datatracker.ietf.org/doc/html/rfc4250)
  <br>The Secure Shell (SSH) Protocol Assigned Numbers
- [RFC 4251](https://datatracker.ietf.org/doc/html/rfc4251)
  <br>The Secure Shell (SSH) Protocol Architecture
- [RFC 4252](https://datatracker.ietf.org/doc/html/rfc4252)
  <br>The Secure Shell (SSH) Authentication Protocol
- [RFC 4253](https://datatracker.ietf.org/doc/html/rfc4253)
  <br>The Secure Shell (SSH) Transport Layer Protocol
- [RFC 4254](https://datatracker.ietf.org/doc/html/rfc4254)
  <br>The Secure Shell (SSH) Connection Protocol
- [RFC 4255](https://datatracker.ietf.org/doc/html/rfc4255)
  <br>Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints
- [RFC 4256](https://datatracker.ietf.org/doc/html/rfc4256)
  <br>Generic Message Exchange Authentication for the Secure Shell Protocol (SSH)
- [RFC 4344](https://datatracker.ietf.org/doc/html/rfc4344)
  <br>The Secure Shell (SSH) Transport Layer Encryption Modes
- [RFC 4419](https://datatracker.ietf.org/doc/html/rfc4419)
  <br>Diffie-Hellman Group Exchange for the Secure Shell (SSH) Transport Layer Protocol
- [RFC 4819](https://www.rfc-editor.org/rfc/rfc4819.html)
  <br>Secure Shell Public Key Subsystem
- [RFC 5656](https://datatracker.ietf.org/doc/html/rfc5656)
  <br>Elliptic Curve Algorithm Integration in the Secure Shell Transport Layer
- [RFC 6668](https://datatracker.ietf.org/doc/html/rfc6668)
  <br>SHA-2 Data Integrity Verification for the Secure Shell (SSH) Transport Layer Protocol
- [RFC 8160](https://datatracker.ietf.org/doc/html/rfc8160)
  <br>IUTF8 Terminal Mode in Secure Shell (SSH)
- [RFC 8308](https://datatracker.ietf.org/doc/html/rfc8308)
  <br>Extension Negotiation in the Secure Shell (SSH) Protocol
- [RFC 8332](https://datatracker.ietf.org/doc/html/rfc8332)
  <br>Use of RSA Keys with SHA-256 and SHA-512 in the Secure Shell (SSH) Protocol
- [RFC 8709](https://datatracker.ietf.org/doc/html/rfc8709)
  <br>Ed25519 and Ed448 Public Key Algorithms for the Secure Shell (SSH) Protocol
- [RFC 8731](https://datatracker.ietf.org/doc/html/rfc8731)
  <br>Secure Shell (SSH) Key Exchange Method Using Curve25519 and Curve448
- [draft-miller-secsh-umac-01](https://datatracker.ietf.org/doc/html/draft-miller-secsh-umac-01.html)
  <br>The use of UMAC in the SSH Transport Layer Protocol

- [SSH implementation comparison](https://ssh-comparison.quendi.de/comparison/mac.html)
- [OpenSSH extensions](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL)
