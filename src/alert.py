from dataclasses import dataclass

from buffer import Buffer
from const import AlertDescription as Description
from const import AlertLevel as Level


@dataclass
class Alert:
    """https://datatracker.ietf.org/doc/html/rfc8446#section-6"""

    level: Level
    description: Description

    def __bytes__(self):
        return bytes(self.level) + bytes(self.description)

    @classmethod
    def from_bytes(cls, payload: bytes):
        if len(payload) != 2:
            raise ValueError("Alert must be 2 bytes long")

        buf = Buffer(payload)

        level = Level(buf.pull_uint8())
        description = Description(buf.pull_uint8())

        return cls(level, description)
