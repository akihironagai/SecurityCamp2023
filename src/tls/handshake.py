from dataclasses import dataclass
from typing import Protocol, Sequence

from const import CipherSuite, HandshakeType
from extension import Extension
from variable import seq_var_bytes, var_bytes


@dataclass(frozen=True)
class HandshakeMessage(Protocol):
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4"""

    msg_type: HandshakeType

    def __bytes__(self) -> bytes:
        ...


@dataclass(frozen=True)
class ClientHello(HandshakeMessage):
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2"""

    msg_type = HandshakeType.CLIENT_HELLO

    random: bytes
    cipher_suites: Sequence[CipherSuite]
    extensions: Sequence[Extension]

    def __bytes__(self):
        return (
            b"\x03\x03"  # legacy_version
            + self.random
            + b"\x00"  # legacy_session_id
            + seq_var_bytes(self.cipher_suites, 2)
            + b"\x01\x00"  # legacy_compression_methods
            + seq_var_bytes(self.extensions, 2)
        )


@dataclass(frozen=True)
class ServerHello(HandshakeMessage):
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3"""

    msg_type = HandshakeType.SERVER_HELLO

    random: bytes
    legacy_session_id_echo: bytes
    cipher_suite: CipherSuite
    extensions: Sequence[Extension]

    def __bytes__(self):
        return (
            b"\x03\x03"  # legacy_version
            + self.random
            + var_bytes(self.legacy_session_id_echo, 1)
            + bytes(self.cipher_suite)
            + b"\x00"  # legacy_compression_method
            + seq_var_bytes(self.extensions, 2)
        )


@dataclass
class Handshake:
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4"""

    handshake_type: HandshakeType
    message: HandshakeMessage

    def __bytes__(self):
        return bytes(self.handshake_type) + var_bytes(self.message, 3)
