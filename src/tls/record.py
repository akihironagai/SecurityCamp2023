from dataclasses import dataclass
from enum import IntEnum
from typing import Literal, Self

from protocol_version import ProtocolVersion


class ContentType(IntEnum):
    INVALID = 0
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23

    def __bytes__(self):
        return self.to_bytes(1)


@dataclass
class Record:
    Type = ContentType
    RecordVersion = ProtocolVersion

    type: Type
    legacy_record_version: Literal[RecordVersion.TLS_1_0, RecordVersion.TLS_1_2]
    fragment: bytes

    @classmethod
    def from_bytes(cls, data: bytes):
        records: list[Self] = []
        rest = data
        while True:
            if len(data) < 5:
                raise ValueError("Invalid record length")
            type = cls.Type(rest[0])
            legacy_record_version = cls.RecordVersion.from_bytes(rest[1:3])
            if (
                legacy_record_version != cls.RecordVersion.TLS_1_0
                and legacy_record_version != cls.RecordVersion.TLS_1_2
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
