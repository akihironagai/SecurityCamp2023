from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from extension import Extension
from extension_type import ExtensionType
from key_share_entry import KeyShareEntry
from named_group import NamedGroup
from uncompressed_point_representation import UncompressedPointRepresentation
from variable import Variable


class KeyShareClientHello(Extension):
    """Key share (Client Hello) extension."""

    extension_type = ExtensionType.KEY_SHARE
    extension_data = Variable(
        data=[
            bytes(
                KeyShareEntry(
                    NamedGroup.X25519,
                    Variable(
                        data=X25519PrivateKey.generate()
                        .public_key()
                        .public_bytes_raw(),
                        length_field=2,
                    ),
                ),
            ),
            bytes(
                KeyShareEntry(
                    NamedGroup.SECP256R1,
                    Variable(
                        data=bytes(
                            UncompressedPointRepresentation(NamedGroup.SECP256R1)
                        ),
                        length_field=2,
                    ),
                ),
            ),
        ],
        length_field=2,
    )
