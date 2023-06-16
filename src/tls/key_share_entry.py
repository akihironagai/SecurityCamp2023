from dataclasses import dataclass

from named_group import NamedGroup
from variable import Variable


@dataclass
class KeyShareEntry:
    """Key share entry."""

    group: NamedGroup
    key_exchange: Variable

    def __bytes__(self):
        return bytes(self.group) + bytes(self.key_exchange)
