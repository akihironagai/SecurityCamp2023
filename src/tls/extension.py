from extension_type import ExtensionType
from opaque import Opaque


class Extension:
    """Extension."""

    extension_type: ExtensionType
    extension_data: Opaque

    def __bytes__(self):
        return bytes(self.extension_type) + bytes(self.extension_data)
