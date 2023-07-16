from dataclasses import dataclass
from typing import Generic, Sequence, SupportsBytes, TypeVar

T = TypeVar("T", bound=SupportsBytes)


@dataclass(frozen=True)
class SequenceVariable(Generic[T]):
    value: Sequence[T]
    value_size: int = 1

    def __bytes__(self):
        return len(self).to_bytes(self.value_size) + b"".join(
            bytes(v) for v in self.value
        )

    def __len__(self):
        return sum(len(bytes(v)) for v in self.value)


def seq_var_bytes(value: Sequence[T], value_size: int = 1):
    return bytes(SequenceVariable(value, value_size))


@dataclass(frozen=True)
class BytesVariable:
    value: SupportsBytes
    value_size: int = 1

    def __bytes__(self):
        return len(self).to_bytes(self.value_size) + bytes(self.value)

    def __len__(self):
        return len(bytes(self.value))


def var_bytes(value: SupportsBytes, value_size: int = 1):
    return bytes(BytesVariable(value, value_size))
