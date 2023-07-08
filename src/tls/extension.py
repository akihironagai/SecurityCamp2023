from dataclasses import dataclass, field
from typing import Protocol, Self, Sequence

from const import (
    ExtensionType,
    HandshakeType,
    NamedGroup,
    ProtocolVersion,
    SignatureScheme,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from variable import seq_var_bytes, var_bytes


class ExtensionData(Protocol):
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8"""

    extension_type: ExtensionType

    def __bytes__(self) -> bytes:
        ...


@dataclass(frozen=True)
class Extension:
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8"""

    extension_type: ExtensionType = field(init=False)
    extension_data: ExtensionData

    def __post_init__(self):
        object.__setattr__(self, "extension_type", self.extension_data.extension_type)

    def __bytes__(self):
        return bytes(self.extension_type) + var_bytes(self.extension_data, 2)

    @classmethod
    def from_bytes(cls, encoded_extensions: bytes):
        extensions_length = int.from_bytes(encoded_extensions[:2])
        assert extensions_length == len(encoded_extensions[2:])

        encoded_extensions = encoded_extensions[2:]

        extensions: list[Self] = []

        while True:
            extension_type = ExtensionType(int.from_bytes(encoded_extensions[:2]))
            extension_data_length = int.from_bytes(encoded_extensions[2:4])
            extension_data = encoded_extensions[4 : 4 + extension_data_length]

            if extension_type == ExtensionType.SERVER_NAME:
                host_name = extension_data[5:].decode()
                extensions.append(cls(ServerNameList(host_name)))
            elif extension_type == ExtensionType.SUPPORTED_GROUPS:
                named_group_list = [
                    NamedGroup(int.from_bytes(group))
                    for group in extension_data[3:].split(b"\x00")
                ]
                extensions.append(cls(NamedGroupList(named_group_list)))
            elif extension_type == ExtensionType.SIGNATURE_ALGORITHMS:
                extension_data = extension_data[2:]
                supported_signature_algorithms: list[SignatureScheme] = []
                while len(extension_data) > 0:
                    supported_signature_algorithms.append(
                        SignatureScheme(int.from_bytes(extension_data[:2]))
                    )
                    extension_data = extension_data[2:]
                extensions.append(
                    cls(SignatureSchemeList(supported_signature_algorithms))
                )
            else:
                raise NotImplementedError

            encoded_extensions = encoded_extensions[4 + extension_data_length :]
            if len(encoded_extensions) == 0:
                break

        return extensions


@dataclass(frozen=True)
class ServerNameList(ExtensionData):
    """https://datatracker.ietf.org/doc/html/rfc6066#section-3"""

    extension_type = ExtensionType.SERVER_NAME
    host_name: str

    def __bytes__(self):
        SERVER_NAME = b"\x00"
        return var_bytes(SERVER_NAME + var_bytes(self.host_name.encode(), 2), 2)


@dataclass(frozen=True)
class NamedGroupList(ExtensionData):
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7"""

    extension_type = ExtensionType.SUPPORTED_GROUPS
    named_group_list: Sequence[NamedGroup]

    def __bytes__(self):
        return seq_var_bytes(self.named_group_list, 2)


@dataclass(frozen=True)
class SignatureSchemeList(ExtensionData):
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3"""

    extension_type = ExtensionType.SIGNATURE_ALGORITHMS
    supported_signature_algorithms: Sequence[SignatureScheme]

    def __bytes__(self):
        return seq_var_bytes(self.supported_signature_algorithms, 2)


@dataclass(frozen=True)
class KeyShareEntry:
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8"""

    public_key: ec.EllipticCurvePublicKey | x25519.X25519PublicKey
    group: NamedGroup = field(init=False)
    key_exchange: bytes = field(init=False)

    def __post_init__(self):
        if isinstance(self.public_key, x25519.X25519PublicKey):
            object.__setattr__(self, "group", NamedGroup.X25519)
            object.__setattr__(self, "key_exchange", self.public_key.public_bytes_raw())
        elif isinstance(self.public_key.curve, ec.SECP256R1):
            object.__setattr__(self, "group", NamedGroup.SECP256R1)
            object.__setattr__(
                self,
                "key_exchange",
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint,
                ),
            )
        elif isinstance(self.public_key.curve, ec.SECP384R1):
            object.__setattr__(self, "group", NamedGroup.SECP384R1)
            object.__setattr__(
                self,
                "key_exchange",
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint,
                ),
            )
        else:
            raise ValueError("Unsupported key")

    def __bytes__(self):
        return bytes(self.group) + var_bytes(self.key_exchange, 2)


@dataclass(frozen=True)
class KeyShareClientHello(ExtensionData):
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8"""

    extension_type = ExtensionType.KEY_SHARE
    client_shares: Sequence[KeyShareEntry]

    def __post_init__(self):
        l = [i.group for i in self.client_shares]
        assert (len(set(l)) - len(l)) == 0

    def __bytes__(self):
        return seq_var_bytes([bytes(i.key_exchange) for i in self.client_shares], 2)


@dataclass(frozen=True)
class KeyShareHelloRetryRequest(ExtensionData):
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8"""

    extension_type = ExtensionType.KEY_SHARE
    selected_group: NamedGroup

    def __bytes__(self):
        return bytes(self.selected_group)


@dataclass(frozen=True)
class KeyShareServerHello(ExtensionData):
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8"""

    extension_type = ExtensionType.KEY_SHARE
    server_share: KeyShareEntry

    def __bytes__(self):
        return var_bytes(self.server_share, 2)


@dataclass(frozen=True)
class SupportedVersions(ExtensionData, Protocol):
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1"""

    extension_type = ExtensionType.SUPPORTED_VERSIONS
    handshake_msg_type: HandshakeType


@dataclass(frozen=True)
class SupportedVersionsClientHello(SupportedVersions):
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1"""

    handshake_msg_type = HandshakeType.CLIENT_HELLO
    versions: Sequence[ProtocolVersion]

    def __bytes__(self):
        return seq_var_bytes(self.versions, 1)


@dataclass(frozen=True)
class SupportedVersionsServerHello(SupportedVersions):
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1"""

    handshake_msg_type = HandshakeType.SERVER_HELLO
    selected_version: ProtocolVersion

    def __bytes__(self):
        return bytes(self.selected_version)


if __name__ == "__main__":
    print(
        Extension.from_bytes(
            bytes.fromhex(
                "00320000000e000c0000096c6f63616c686f7374000a00040002001d000d00140012040105010601040305030603080408050806"
            )
        )
    )
