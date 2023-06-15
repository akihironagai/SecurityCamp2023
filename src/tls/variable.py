class Variable:
    """Variable data type."""

    def __init__(self, data: bytes | list[bytes] = b"", length_field: int = 0):
        if isinstance(data, bytes):
            self.data = data
        else:
            self.data = b"".join(data)
        self.length_field = length_field

    def __bytes__(self):
        if self.length_field == 0:
            return self.data
        return len(self.data).to_bytes(self.length_field, "big") + self.data
