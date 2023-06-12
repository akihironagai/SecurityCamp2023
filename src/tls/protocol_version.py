from enum import IntEnum


class ProtocolVersion(IntEnum):
    """Protocol version enumeration."""

    TLS_1_0 = 0x0301
    TLS_1_1 = 0x0302
    TLS_1_2 = 0x0303
    TLS_1_3 = 0x0304

    def __bytes__(self):
        return self.value.to_bytes(2, "big")
