from dataclasses import dataclass
from enum import IntEnum

from variable import Variable


class HandshakeType(IntEnum):
    """Handshake type enumeration."""

    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    NEW_SESSION_TICKET = 4
    END_OF_EARLY_DATA = 5
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    CERTIFICATE_REQUEST = 13
    CERTIFICATE_VERIFY = 15
    FINISHED = 20
    KEY_UPDATE = 24
    MESSAGE_HASH = 254

    def __bytes__(self):
        return self.value.to_bytes(1, "big")


@dataclass
class Handshake:
    """Handshake protocol."""

    msg_type: HandshakeType

    @property
    def length(self):
        return len(bytes(self.msg)).to_bytes(3, "big")

    msg: Variable

    def __bytes__(self):
        return bytes(self.msg_type) + self.length + bytes(self.msg)
