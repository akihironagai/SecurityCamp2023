from typing import Literal

from cryptography.hazmat.primitives.asymmetric import ec
from named_group import NamedGroup


class UncompressedPointRepresentation:
    """Uncompressed point representation."""

    legacy_form = 4

    def __init__(
        self,
        group_name: Literal[
            NamedGroup.SECP256R1, NamedGroup.SECP384R1, NamedGroup.SECP521R1
        ],
    ):
        if group_name == NamedGroup.SECP256R1:
            private_key = ec.generate_private_key(ec.SECP256R1())
        elif group_name == NamedGroup.SECP384R1:
            private_key = ec.generate_private_key(ec.SECP384R1())
        else:
            private_key = ec.generate_private_key(ec.SECP521R1())
        key_size = private_key.public_key().public_numbers().curve.key_size // 8
        self.x = private_key.public_key().public_numbers().x.to_bytes(key_size, "big")
        self.y = private_key.public_key().public_numbers().y.to_bytes(key_size, "big")

    def __bytes__(self):
        return self.legacy_form.to_bytes(1, "big") + self.x + self.y
