from enum import IntEnum


class NamedGroup(IntEnum):
    """Named group enumeration."""

    # Elliptic Curve Groups (ECDHE)
    SECP256R1 = 0x0017
    SECP384R1 = 0x0018
    SECP521R1 = 0x0019
    X25519 = 0x001D
    X448 = 0x001E

    # Finite Field Groups (DHE)
    FFDHE2048 = 0x0100
    FFDHE3072 = 0x0101
    FFDHE4096 = 0x0102
    FFDHE6144 = 0x0103
    FFDHE8192 = 0x0104

    def __bytes__(self):
        return self.value.to_bytes(2, "big")
