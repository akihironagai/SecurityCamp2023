from dataclasses import dataclass

from const import AlertDescription, AlertLevel


@dataclass
class Alert:
    level: AlertLevel
    description: AlertDescription

    def __bytes__(self):
        return bytes(self.level) + bytes(self.description)
