from extension_type import ExtensionType
from variable import Variable


class Extension:
    """Extension."""

    extension_type: ExtensionType
    extension_data: Variable

    def __bytes__(self):
        return bytes(self.extension_type) + bytes(self.extension_data)
