from dataclasses import dataclass
from typing import Generic, Sequence, SupportsBytes, TypeVar

T = TypeVar("T", bound=SupportsBytes)


@dataclass
class Variable(Generic[T]):
    data: T | Sequence[T]
    length_in_bytes: int

    def __bytes__(self):
        length = self.length_in_bytes
        if isinstance(self.data, Sequence):
            data = b"".join(bytes(d) for d in self.data)
        else:
            data = bytes(self.data)
        return len(data).to_bytes(length) + data
