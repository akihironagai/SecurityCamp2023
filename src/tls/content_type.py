from enum import IntEnum


class ContentType(IntEnum):
    """Content type."""

    INVALID = 0
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23
    HEARTBEAT = 24

    def __bytes__(self):
        return self.value.to_bytes(1, "big")
