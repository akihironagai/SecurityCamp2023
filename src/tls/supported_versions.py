from extension import Extension
from extension_type import ExtensionType
from opaque import Opaque
from protocol_version import ProtocolVersion


class SupportedVersions(Extension):
    """Supported versions extension."""

    extension_type = ExtensionType.SUPPORTED_VERSIONS
    extension_data = Opaque(
        data=b"".join([bytes(ProtocolVersion.TLS_1_3)]), length_field=2
    )
