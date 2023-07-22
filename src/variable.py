from dataclasses import dataclass
from typing import Generic, Sequence, SupportsBytes, TypeVar

T = TypeVar("T", bound=SupportsBytes)


@dataclass(frozen=True)
class SequenceVariable(Generic[T]):
    value: Sequence[T]
    value_size: int = 1

    def __bytes__(self):
        value = b"".join(bytes(v) for v in self.value)
        value_size = len(self).to_bytes(self.value_size, "big")
        return value_size + value

    def __len__(self):
        return sum(len(bytes(v)) for v in self.value)


@dataclass(frozen=True)
class BytesVariable:
    value: SupportsBytes
    value_size: int = 1

    def __bytes__(self):
        return len(self).to_bytes(self.value_size) + bytes(self.value)

    def __len__(self):
        return len(bytes(self.value))


def len_bytes(value: SupportsBytes | Sequence[T], value_size: int = 1):
    if isinstance(value, SupportsBytes):
        return bytes(BytesVariable(value, value_size))
    return bytes(SequenceVariable(value, value_size))
