from dataclasses import dataclass
from typing import Protocol, Sequence

from buffer import Buffer
from const import CipherSuite, HandshakeType
from extension import Extension
from variable import len_bytes


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
            + len_bytes(self.cipher_suites, 2)
            + b"\x01\x00"  # legacy_compression_methods
            + len_bytes(self.extensions, 2)
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
            + len_bytes(self.legacy_session_id_echo, 1)
            + bytes(self.cipher_suite)
            + b"\x00"  # legacy_compression_method
            + len_bytes(self.extensions, 2)
        )


@dataclass(frozen=True)
class Handshake:
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4"""

    handshake_type: HandshakeType
    message: HandshakeMessage

    @classmethod
    def from_bytes(cls, payload: bytes):
        if len(payload) < 4:
            raise ValueError("Handshake must be at least 4 bytes long")

        buf = Buffer(payload)

        handshake_type = HandshakeType(buf.pull_uint8())
        encoded_message = buf.pull_bytes_with_uint24_length()

        match handshake_type:
            case HandshakeType.CLIENT_HELLO:
                message = ClientHello.from_bytes(encoded_message)
            case HandshakeType.SERVER_HELLO:
                message = ServerHello.from_bytes(encoded_message)
            case _:
                raise NotImplementedError

        return cls(handshake_type, message)
