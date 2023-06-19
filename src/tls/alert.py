from dataclasses import dataclass
from enum import IntEnum


class AlertLevel(IntEnum):
    WARNING = 1
    FATAL = 2


class AlertDescription(IntEnum):
    CLOSE_NOTIFY = 0
    UNEXPECTED_MESSAGE = 10
    BAD_RECORD_MAC = 20
    RECORD_OVERFLOW = 22
    HANDSHAKE_FAILURE = 40
    BAD_CERTIFICATE = 42
    UNSUPPORTED_CERTIFICATE = 43
    CERTIFICATE_REVOKED = 44
    CERTIFICATE_EXPIRED = 45
    CERTIFICATE_UNKNOWN = 46
    ILLEGAL_PARAMETER = 47
    UNKNOWN_CA = 48
    ACCESS_DENIED = 49
    DECODE_ERROR = 50
    DECRYPT_ERROR = 51
    PROTOCOL_VERSION = 70
    INSUFFICIENT_SECURITY = 71
    INTERNAL_ERROR = 80
    INAPPROPRIATE_FALLBACK = 86
    USER_CANCELED = 90
    MISSING_EXTENSION = 109
    UNSUPPORTED_EXTENSION = 110
    UNRECOGNIZED_NAME = 112
    BAD_CERTIFICATE_STATUS_RESPONSE = 113
    UNKNOWN_PSK_IDENTITY = 115
    CERTIFICATE_REQUIRED = 116
    NO_APPLICATION_PROTOCOL = 120


@dataclass
class Alert:
    level: AlertLevel
    description: AlertDescription

    Level = AlertLevel
    Description = AlertDescription

    def __bytes__(self):
        level = self.level.to_bytes()
        description = self.description.to_bytes()
        return level + description

    @classmethod
    def from_bytes(cls, data: bytes):
        level = cls.Level(data[0])
        description = cls.Description(data[1])
        return cls(level, description)

    @staticmethod
    def parse(data: bytes):
        return Alert.from_bytes(data)

    @staticmethod
    def to_bytes(alert):
        return bytes(alert)
