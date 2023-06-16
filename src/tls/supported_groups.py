from extension import Extension
from extension_type import ExtensionType
from named_group import NamedGroup
from variable import Variable


class SupportedGroups(Extension):
    """Supported groups extension."""

    extension_type = ExtensionType.SUPPORTED_GROUPS
    extension_data = Variable(
        data=bytes(
            Variable(
                data=[
                    bytes(NamedGroup.SECP256R1),
                    bytes(NamedGroup.SECP384R1),
                    bytes(NamedGroup.SECP521R1),
                    bytes(NamedGroup.X25519),
                    bytes(NamedGroup.X448),
                    bytes(NamedGroup.FFDHE2048),
                    bytes(NamedGroup.FFDHE3072),
                    bytes(NamedGroup.FFDHE4096),
                    bytes(NamedGroup.FFDHE6144),
                    bytes(NamedGroup.FFDHE8192),
                ],
                length_field=2,
            )
        ),
        length_field=2,
    )
