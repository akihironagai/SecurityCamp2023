from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Protocol, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh, ec, x448, x25519
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)
from protocol_version import ProtocolVersion
from variable import Variable


class HandshakeType(IntEnum):
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    NEW_SESSION_TICKET = 4
    END_OF_EARLY_DATA = 5
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    CERTIFICATE_REQUEST = 13
    CERTIFICATE_VERIFY = 15
    FINISHED = 20
    KEY_UPDATE = 24
    MESSAGE_HASH = 254

    def __bytes__(self):
        return self.to_bytes()


class CipherSuite(IntEnum):
    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    TLS_AES_128_CCM_SHA256 = 0x1304
    TLS_AES_128_CCM_8_SHA256 = 0x1305

    def __bytes__(self):
        return self.to_bytes(2)


class ExtensionType(IntEnum):
    SERVER_NAME = 0
    MAX_FRAGMENT_LENGTH = 1
    STATUS_REQUEST = 5
    SUPPORTED_GROUPS = 10
    SIGNATURE_ALGORITHMS = 13
    USE_SRTP = 14
    HEARTBEAT = 15
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16
    SIGNED_CERTIFICATE_TIMESTAMP = 18
    CLIENT_CERTIFICATE_TYPE = 19
    SERVER_CERTIFICATE_TYPE = 20
    PADDING = 21
    PRE_SHARED_KEY = 41
    EARLY_DATA = 42
    SUPPORTED_VERSIONS = 43
    COOKIE = 44
    PSK_KEY_EXCHANGE_MODES = 45
    CERTIFICATE_AUTHORITIES = 47
    OID_FILTERS = 48
    POST_HANDSHAKE_AUTH = 49
    SIGNATURE_ALGORITHMS_CERT = 50
    KEY_SHARE = 51

    def __bytes__(self):
        return self.to_bytes(2)


class SignatureScheme(IntEnum):
    # RSASSA-PKCS1-v1_5 algorithms
    RSA_PKCS1_SHA256 = 0x0401
    RSA_PKCS1_SHA384 = 0x0501
    RSA_PKCS1_SHA512 = 0x0601

    # ECDSA algorithms
    ECDSA_SECP256R1_SHA256 = 0x0403
    ECDSA_SECP384R1_SHA384 = 0x0503
    ECDSA_SECP521R1_SHA512 = 0x0603

    # RSASSA-PSS algorithms with public key OID rsaEncryption
    RSA_PSS_RSAE_SHA256 = 0x0804
    RSA_PSS_RSAE_SHA384 = 0x0805
    RSA_PSS_RSAE_SHA512 = 0x0806

    # EdDSA algorithms
    ED25519 = 0x0807
    ED448 = 0x0808

    # RSASSA-PSS algorithms with public key OID RSASSA-PSS
    RSA_PSS_PSS_SHA256 = 0x0809
    RSA_PSS_PSS_SHA384 = 0x080A
    RSA_PSS_PSS_SHA512 = 0x080B

    # Legacy algorithms
    RSA_PKCS1_SHA1 = 0x0201
    ECDSA_SHA1 = 0x0203

    def __bytes__(self):
        return self.to_bytes(2)


class NamedGroup(IntEnum):
    # Elliptic Curve Groups (ECDHE)
    SECP256R1 = 0x0017
    SECP384R1 = 0x0018
    SECP521R1 = 0x0019
    X25519 = 0x001D
    X448 = 0x001E

    # Finite Field Groups (DHE)
    FFDHE2048 = 0x0100
    FFDHE3072 = 0x0101
    FFDHE4096 = 0x0102
    FFDHE6144 = 0x0103
    FFDHE8192 = 0x0104

    def __bytes__(self):
        return self.to_bytes(2)


class Extension(Protocol):
    """Extensions (RFC 8446 Section 4.2)"""

    extension_type: ExtensionType
    extension_data: Any

    def __bytes__(self) -> bytes:
        ...


@dataclass
class ServerNameList(Extension):
    """Server Name Indication (SNI) Extension"""

    @dataclass
    class ServerName:
        host_name: str

        def __bytes__(self):
            host_name = bytes(Variable(self.host_name.encode("utf-8"), 2))
            return b"\x00" + host_name

    extension_type = ExtensionType.SERVER_NAME
    extension_data: Sequence[ServerName]

    def __bytes__(self):
        type = bytes(self.extension_type)
        names = b"".join(bytes(name) for name in self.extension_data)
        return type + bytes(Variable(names, 2))


@dataclass
class SupportedVersions(Extension):
    """Supported Versions Extension (RFC 8446 Section 4.2.1)"""

    Version = ProtocolVersion

    extension_type = ExtensionType.SUPPORTED_VERSIONS
    extension_data: Version | Sequence[Version]

    def __bytes__(self):
        type = bytes(self.extension_type)

        if isinstance(self.extension_data, self.Version):
            return type + bytes(self.extension_data)
        return type + bytes(Variable(bytes(Variable(self.extension_data, 1)), 2))


@dataclass
class SignatureAlgorithms(Extension):
    """Signature Algorithms Extension (RFC 8446 Section 4.2.3)"""

    extension_type = ExtensionType.SIGNATURE_ALGORITHMS
    extension_data: Sequence[SignatureScheme]

    def __bytes__(self):
        type = bytes(self.extension_type)
        data = bytes(Variable(self.extension_data, 2))
        return type + data


@dataclass
class SupportedGroups(Extension):
    """Supported Groups Extension (RFC 8446 Section 4.2.7)"""

    extension_type = ExtensionType.SUPPORTED_GROUPS
    extension_data: Sequence[NamedGroup]

    def __bytes__(self):
        type = bytes(self.extension_type)
        data = bytes(Variable(self.extension_data, 2))
        return type + data


@dataclass
class KeyShare(Extension):
    """Key Share Extension (RFC 8446 Section 4.2.8)"""

    @dataclass
    class KeyShareEntry:
        key_exchange: PrivateKeyTypes | PublicKeyTypes

        def __bytes__(self):
            DHKey = dh.DHPrivateKey | dh.DHPublicKey
            ECKey = ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey
            X25519Key = x25519.X25519PrivateKey | x25519.X25519PublicKey
            X448Key = x448.X448PrivateKey | x448.X448PublicKey

            SECP256R1 = NamedGroup.SECP256R1
            SECP384R1 = NamedGroup.SECP384R1
            SECP521R1 = NamedGroup.SECP521R1
            X25519 = NamedGroup.X25519
            X448 = NamedGroup.X448

            FFDHE2048 = NamedGroup.FFDHE2048
            FFDHE3072 = NamedGroup.FFDHE3072
            FFDHE4096 = NamedGroup.FFDHE4096
            FFDHE6144 = NamedGroup.FFDHE6144
            FFDHE8192 = NamedGroup.FFDHE8192

            group: NamedGroup
            key = self.key_exchange

            if isinstance(key, DHKey):
                match key.key_size:
                    case 2048:
                        group = FFDHE2048
                    case 3072:
                        group = FFDHE3072
                    case 4096:
                        group = FFDHE4096
                    case 6144:
                        group = FFDHE6144
                    case 8192:
                        group = FFDHE8192
                    case _:
                        raise ValueError(f"Unsupported key size: {key.key_size}")
                if isinstance(key, PrivateKeyTypes):
                    key = key.public_key()
                p = key.parameters().parameter_numbers().p
                y = key.public_numbers().y
                key = y.to_bytes((p.bit_length() + 7) // 8)
            elif isinstance(key, ECKey):
                if isinstance(key.curve, ec.SECP256R1):
                    group = SECP256R1
                elif isinstance(key.curve, ec.SECP384R1):
                    group = SECP384R1
                elif isinstance(key.curve, ec.SECP521R1):
                    group = SECP521R1
                else:
                    raise ValueError(f"Unsupported curve: {key.curve.name}")
                if isinstance(key, ec.EllipticCurvePrivateKey):
                    key = key.public_key()
                key = key.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint,
                )
            elif isinstance(key, (X25519Key, X448Key)):
                group = X25519 if isinstance(key, X25519Key) else X448
                if isinstance(key, PrivateKeyTypes):
                    key = key.public_key()
                key = key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            else:
                raise TypeError(f"Unsupported key type: {type(key)}")
            return bytes(group) + key

    extension_type = ExtensionType.KEY_SHARE
    extension_data: Sequence[PrivateKeyTypes] | NamedGroup | PublicKeyTypes

    def __bytes__(self):
        type = bytes(self.extension_type)
        data = self.extension_data
        if isinstance(data, NamedGroup):
            data = bytes(data)
        elif isinstance(data, PublicKeyTypes):
            data = bytes(self.KeyShareEntry(data))
        else:
            data = b"".join(bytes(self.KeyShareEntry(key)) for key in data)
        return type + bytes(data)


@dataclass
class ClientHello:
    """Client Hello (RFC 8446 Section 4.1.2)"""

    random: bytes
    cipher_suites: Sequence[CipherSuite]
    extensions: Sequence[Extension]

    def __bytes__(self):
        return (
            b"\x03\x03"  # legacy_version
            + self.random
            + b"\x00"  # legacy_session_id
            + bytes(Variable(self.cipher_suites, 2))
            + b"\x01\x00"  # legacy_compression_methods
            + bytes(Variable(self.extensions, 2))
        )


@dataclass
class ServerHello:
    """Server Hello (RFC 8446 Section 4.1.3)"""

    random: bytes
    legacy_session_id_echo: bytes
    cipher_suite: CipherSuite
    extensions: Sequence[Extension]

    def __bytes__(self):
        return (
            b"\x03\x03"  # legacy_version
            + self.random
            + bytes(Variable(self.legacy_session_id_echo, 1))
            + bytes(self.cipher_suite)
            + b"\x00"  # legacy_compression_method
            + bytes(Variable(self.extensions, 2))
        )
