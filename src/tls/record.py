from dataclasses import dataclass
from typing import Literal, Self

from const import ContentType, ProtocolVersion


@dataclass
class Record:
    type: ContentType
    legacy_record_version: Literal[ProtocolVersion.TLS_1_0, ProtocolVersion.TLS_1_2]
    fragment: bytes

    def __bytes__(self):
        return (
            bytes(self.type)
            + bytes(self.legacy_record_version)
            + len(self.fragment).to_bytes(2, "big")
            + self.fragment
        )

    @classmethod
    def from_bytes(cls, data: bytes):
        records: list[Self] = []
        rest = data
        while True:
            if len(data) < 5:
                raise ValueError("Invalid record length")
            type = ContentType(rest[0])
            legacy_record_version = ProtocolVersion.from_bytes(rest[1:3])
            if (
                legacy_record_version != ProtocolVersion.TLS_1_0
                and legacy_record_version != ProtocolVersion.TLS_1_2
            ):
                raise ValueError("Invalid legacy record version")
            length = int.from_bytes(rest[3:5])
            fragment = rest[5 : 5 + length]
            records.append(cls(type, legacy_record_version, fragment))
            rest = rest[5 + length :]
            if len(rest) == 0:
                break
            elif len(rest) < 5:
                raise ValueError("Invalid record length")
        return records
