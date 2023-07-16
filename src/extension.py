from dataclasses import dataclass, field
from typing import Protocol, Self, Sequence

from buffer import Buffer
from const import ExtensionType, NamedGroup, ProtocolVersion, SignatureScheme
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from variable import seq_var_bytes, var_bytes


class ExtensionData(Protocol):
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8"""

    extension_type: ExtensionType

    def __bytes__(self) -> bytes:
        ...

    @classmethod
    def from_bytes(cls, encoded_extension_data: bytes) -> Self:
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
        buf = Buffer(encoded_extensions)
        buf = Buffer(buf.pull_bytes_with_uint16_length())
        extensions: list[ExtensionData] = []

        while buf.capacity > 0:
            extension_type = ExtensionType(buf.pull_uint16())

            match extension_type:
                case ExtensionType.SERVER_NAME:
                    extensions.append(ServerNameList.from_bytes(bytes(buf.buffer)))
                    buf.pull_bytes_with_uint16_length()
                case ExtensionType.SUPPORTED_GROUPS:
                    extensions.append(
                        NamedGroupList.from_bytes(buf.pull_bytes_with_uint16_length())
                    )
                case ExtensionType.SIGNATURE_ALGORITHMS:
                    extensions.append(
                        SignatureSchemeList.from_bytes(
                            buf.pull_bytes_with_uint16_length()
                        )
                    )
                case ExtensionType.KEY_SHARE:
                    if buf.capacity == 2:
                        extensions.append(
                            KeyShareHelloRetryRequest.from_bytes(bytes(buf.buffer))
                        )
                    else:
                        double_length = buf.peek_bytes(4)
                        first_length = int.from_bytes(double_length[:2], "big")
                        second_length = int.from_bytes(double_length[2:], "big")
                        if first_length == second_length + 2:
                            extensions.append(
                                KeyShareClientHello.from_bytes(bytes(buf.buffer))
                            )
                        else:
                            # server hello
                            extensions.append(
                                KeyShareServerHello.from_bytes(bytes(buf.buffer))
                            )
                            buf.pull_bytes_with_uint16_length()
                case ExtensionType.SUPPORTED_VERSIONS:
                    extensions.append(
                        SupportedVersions.from_bytes(
                            buf.pull_bytes_with_uint16_length()
                        )
                    )
                case _:
                    raise NotImplementedError(f"{extension_type} is not implemented")
        return extensions


@dataclass(frozen=True)
class ServerNameList(ExtensionData):
    """https://datatracker.ietf.org/doc/html/rfc6066#section-3"""

    extension_type = ExtensionType.SERVER_NAME
    host_name: str

    def __bytes__(self):
        SERVER_NAME = b"\x00"
        return var_bytes(SERVER_NAME + var_bytes(self.host_name.encode(), 2), 2)

    @classmethod
    def from_bytes(cls, encoded_extension_data: bytes):
        buf = Buffer(encoded_extension_data)
        buf = Buffer(buf.pull_bytes_with_uint16_length())
        buf = Buffer(buf.pull_bytes_with_uint16_length())
        name_type = buf.pull_uint8()

        if name_type != 0:
            raise NotImplementedError

        host_name = buf.pull_bytes_with_uint16_length().decode()

        return cls(host_name)


@dataclass(frozen=True)
class NamedGroupList(ExtensionData):
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7"""

    extension_type = ExtensionType.SUPPORTED_GROUPS
    named_group_list: Sequence[NamedGroup]

    def __bytes__(self):
        return seq_var_bytes(self.named_group_list, 2)

    @classmethod
    def from_bytes(cls, encoded_extension_data: bytes):
        buf = Buffer(encoded_extension_data)
        buf = Buffer(buf.pull_bytes_with_uint16_length())
        buf = Buffer(buf.pull_bytes_with_uint16_length())

        named_groups: list[NamedGroup] = []

        while buf.capacity > 0:
            named_group = NamedGroup(buf.pull_uint16())
            named_groups.append(named_group)

        return cls(named_groups)


@dataclass(frozen=True)
class SignatureSchemeList(ExtensionData):
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3"""

    extension_type = ExtensionType.SIGNATURE_ALGORITHMS
    supported_signature_algorithms: Sequence[SignatureScheme]

    def __bytes__(self):
        return seq_var_bytes(self.supported_signature_algorithms, 2)

    @classmethod
    def from_bytes(cls, encoded_extension_data: bytes):
        buf = Buffer(encoded_extension_data)
        buf = Buffer(buf.pull_bytes_with_uint16_length())
        buf = Buffer(buf.pull_bytes_with_uint16_length())

        supported_signature_algorithms: list[SignatureScheme] = []

        while buf.capacity > 0:
            supported_signature_algorithm = SignatureScheme(buf.pull_uint16())
            supported_signature_algorithms.append(supported_signature_algorithm)

        return cls(supported_signature_algorithms)


@dataclass(frozen=True)
class KeyShareEntry:
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8"""

    public_key: ec.EllipticCurvePublicKey | x25519.X25519PublicKey
    group: NamedGroup = field(init=False, repr=False)
    key_exchange: bytes = field(init=False, repr=False)

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

    @classmethod
    def from_bytes(cls, encoded_extension_data: bytes):
        buf = Buffer(encoded_extension_data)
        buf = Buffer(buf.pull_bytes_with_uint16_length())
        buf = Buffer(buf.pull_bytes_with_uint16_length())

        client_shares: list[KeyShareEntry] = []

        while buf.capacity > 0:
            group = NamedGroup(buf.pull_uint16())
            key_exchange = buf.pull_bytes_with_uint16_length()
            if group == NamedGroup.X25519:
                public_key = x25519.X25519PublicKey.from_public_bytes(key_exchange)
            else:
                raise NotImplementedError
            client_shares.append(KeyShareEntry(public_key))

        return cls(client_shares)


@dataclass(frozen=True)
class KeyShareHelloRetryRequest(ExtensionData):
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8"""

    extension_type = ExtensionType.KEY_SHARE
    selected_group: NamedGroup

    def __bytes__(self):
        return bytes(self.selected_group)

    @classmethod
    def from_bytes(cls, encoded_extension_data: bytes):
        buf = Buffer(encoded_extension_data)
        buf = Buffer(buf.pull_bytes_with_uint16_length())

        selected_group = NamedGroup(buf.pull_uint16())

        return cls(selected_group)


@dataclass(frozen=True)
class KeyShareServerHello(ExtensionData):
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.8"""

    extension_type = ExtensionType.KEY_SHARE
    server_share: KeyShareEntry

    def __bytes__(self):
        return var_bytes(self.server_share, 2)

    @classmethod
    def from_bytes(cls, encoded_extension_data: bytes):
        buf = Buffer(encoded_extension_data)
        buf = Buffer(buf.pull_bytes_with_uint16_length())

        group = NamedGroup(buf.pull_uint16())
        key_exchange = buf.pull_bytes_with_uint16_length()

        if group == NamedGroup.X25519:
            public_key = x25519.X25519PublicKey.from_public_bytes(key_exchange)
        else:
            raise NotImplementedError

        return cls(KeyShareEntry(public_key))


@dataclass(frozen=True)
class SupportedVersions(ExtensionData):
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1"""

    extension_type = ExtensionType.SUPPORTED_VERSIONS

    versions: Sequence[ProtocolVersion] | None
    selected_version: ProtocolVersion | None

    def __post_init__(self):
        if self.versions is None and self.selected_version is None:
            raise ValueError("versions or selected_version must be set")

        if self.versions and self.selected_version:
            raise ValueError(
                "versions and selected_version cannot be set at the same time"
            )

    def __bytes__(self):
        if self.versions:
            return seq_var_bytes([bytes(i) for i in self.versions], 1)
        elif self.selected_version:
            return bytes(self.selected_version)
        else:
            raise ValueError("versions or selected_version must be set")

    @classmethod
    def from_bytes(cls, encoded_extension_data: bytes):
        buf = Buffer(encoded_extension_data)
        buf = Buffer(buf.pull_bytes_with_uint16_length())

        if buf.capacity == 2:
            return cls(None, ProtocolVersion(buf.pull_uint16()))
        else:
            buf = Buffer(buf.pull_bytes_with_uint8_length())
            versions: list[ProtocolVersion] = []
            while buf.capacity > 0:
                versions.append(ProtocolVersion(buf.pull_uint16()))
            return cls(versions, None)
