from dataclasses import dataclass, field


@dataclass(frozen=True)
class Buffer:
    data: bytes
    buffer: bytearray = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "buffer", bytearray(self.data))

    def __len__(self) -> int:
        return len(self.data)
    
    @property
    def capacity(self) -> int:
        return len(self.buffer)

    def pull_bytes(self, length: int) -> bytes:
        result = self.buffer[:length]
        del self.buffer[:length]
        return bytes(result)

    def pull_uint(self, length: int) -> int:
        return int.from_bytes(self.pull_bytes(length), "big")

    def pull_uint8(self) -> int:
        return self.pull_uint(1)

    def pull_uint16(self) -> int:
        return self.pull_uint(2)

    def pull_uint24(self) -> int:
        return self.pull_uint(3)

    def pull_uint32(self) -> int:
        return self.pull_uint(4)

    def pull_uint64(self) -> int:
        return self.pull_uint(8)

    def pull_bytes_with_uint8_length(self) -> bytes:
        length = self.pull_uint8()
        return self.pull_bytes(length)

    def pull_bytes_with_uint16_length(self) -> bytes:
        length = self.pull_uint16()
        return self.pull_bytes(length)

    def pull_bytes_with_uint24_length(self) -> bytes:
        length = self.pull_uint24()
        return self.pull_bytes(length)

    def pull_bytes_with_uint32_length(self) -> bytes:
        length = self.pull_uint32()
        return self.pull_bytes(length)

    def pull_bytes_with_uint64_length(self) -> bytes:
        length = self.pull_uint64()
        return self.pull_bytes(length)
