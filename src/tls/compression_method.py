from enum import IntEnum


class CompressionMethod(IntEnum):
    """Compression method enumeration."""

    NULL = 0

    def __bytes__(self):
        return self.value.to_bytes(1, "big")
