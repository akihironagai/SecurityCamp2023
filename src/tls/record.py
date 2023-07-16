from dataclasses import dataclass, field
from typing import Literal, Self

from const import ContentType


@dataclass
class Record:
    type: ContentType
    legacy_record_version: Literal[0x0301, 0x0303] = field(repr=False)
    payload: bytes

    def __bytes__(self):
        return (
            bytes(self.type)
            + bytes(self.legacy_record_version)
            + len(self.payload).to_bytes(2, "big")
            + self.payload
        )

    @classmethod
    def from_bytes(cls, data: bytes):
        records: list[Self] = []
        rest = data
        while True:
            if len(data) < 5:
                raise ValueError("Invalid record length")
            type = ContentType(rest[0])
            version = rest[1:3]
            legacy_record_version = int.from_bytes(version, "big")
            if legacy_record_version != 0x0301 and legacy_record_version != 0x0303:
                raise ValueError("Invalid legacy record version")
            length = int.from_bytes(rest[3:5])
            fragment = rest[5 : 5 + length]
            records.append(cls(type, legacy_record_version, fragment))
            rest = rest[5 + length :]
            if len(rest) == 0:
                break
            elif len(rest) < 5:
                raise ValueError("Invalid record length")
        if len(records) == 1:
            return records[0]
        return records
