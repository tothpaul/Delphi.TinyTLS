# Delphi.TinyTLS
Tiny Delphi TLS 1.2 implementation for Windows

this project is just an exploration of TLS protocol.

the goal of the code is not to be secure or performant, but to be comphensible.

use it at your own risk ;)

you can use the either TinyTLS or SChannel engine, the TLS Fragments are readed by FTLSReader in both cases and the Debug unit can displays the protocol details (see $DEFINE TLS_DEBUG)

- 02/27/2025: added SChannel Engine, note that TinyTLS uses BCrypt.dll available only since Windows 10