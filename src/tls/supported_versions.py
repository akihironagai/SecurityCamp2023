from extension import Extension
from extension_type import ExtensionType
from protocol_version import ProtocolVersion
from variable import Variable


class SupportedVersions(Extension):
    """Supported versions extension."""

    extension_type = ExtensionType.SUPPORTED_VERSIONS
    extension_data = Variable(
        data=bytes(Variable(data=[bytes(ProtocolVersion.TLS_1_3)], length_field=1)),
        length_field=2,
    )
