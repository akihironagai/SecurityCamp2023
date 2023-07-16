from enum import IntEnum, unique


@unique
class AlertDescription(IntEnum):
    """https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.2"""

    CLOSE_NOTIFY = 0
    UNEXPECTED_MESSAGE = 10
    BAD_RECORD_MAC = 20
    RECORD_OVERFLOW = 22
    HANDSHAKE_FAILURE = 40
    BAD_CERTIFICATE = 42
    UNSUPPORTED_CERTIFICATE = 43
    CERTIFICATE_REVOKED = 44
    CERTIFICATE_EXPIRED = 45
    CERTIFICATE_UNKNOWN = 46
    ILLEGAL_PARAMETER = 47
    UNKNOWN_CA = 48
    ACCESS_DENIED = 49
    DECODE_ERROR = 50
    DECRYPT_ERROR = 51
    PROTOCOL_VERSION = 70
    INSUFFICIENT_SECURITY = 71
    INTERNAL_ERROR = 80
    INAPPROPRIATE_FALLBACK = 86
    USER_CANCELED = 90
    MISSING_EXTENSION = 109
    UNSUPPORTED_EXTENSION = 110
    UNRECOGNIZED_NAME = 112
    BAD_CERTIFICATE_STATUS_RESPONSE = 113
    UNKNOWN_PSK_IDENTITY = 115
    CERTIFICATE_REQUIRED = 116
    NO_APPLICATION_PROTOCOL = 120

    def __bytes__(self):
        return self.to_bytes()


@unique
class AlertLevel(IntEnum):
    """https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.2"""

    WARNING = 1
    FATAL = 2

    def __bytes__(self):
        return self.to_bytes()


@unique
class CipherSuite(IntEnum):
    """https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.4"""

    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    TLS_AES_128_CCM_SHA256 = 0x1304
    TLS_AES_128_CCM_8_SHA256 = 0x1305

    def __bytes__(self):
        return self.to_bytes(2)


@unique
class ContentType(IntEnum):
    """https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.1"""

    INVALID = 0
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23
    HEARTBEAT = 24

    def __bytes__(self):
        return self.to_bytes(1)


@unique
class ExtensionType(IntEnum):
    """https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1"""

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


@unique
class HandshakeType(IntEnum):
    """https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3"""

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


@unique
class NamedGroup(IntEnum):
    """https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.7"""

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

    # GREASE (RFC 8701)
    GREASE_0A = 0x0A0A
    GREASE_1A = 0x1A1A
    GREASE_2A = 0x2A2A
    GREASE_3A = 0x3A3A
    GREASE_4A = 0x4A4A
    GREASE_5A = 0x5A5A
    GREASE_6A = 0x6A6A
    GREASE_7A = 0x7A7A
    GREASE_8A = 0x8A8A
    GREASE_9A = 0x9A9A
    GREASE_AA = 0xAAAA
    GREASE_BA = 0xBABA
    GREASE_CA = 0xCACA
    GREASE_DA = 0xDADA
    GREASE_EA = 0xEAEA
    GREASE_FA = 0xFAFA

    def __bytes__(self):
        return self.to_bytes(2)


@unique
class ProtocolVersion(IntEnum):
    TLS_1_0 = 0x0301
    TLS_1_1 = 0x0302
    TLS_1_2 = 0x0303
    TLS_1_3 = 0x0304

    # GREASE (RFC 8701)
    GREASE_0A = 0x0A0A
    GREASE_1A = 0x1A1A
    GREASE_2A = 0x2A2A
    GREASE_3A = 0x3A3A
    GREASE_4A = 0x4A4A
    GREASE_5A = 0x5A5A
    GREASE_6A = 0x6A6A
    GREASE_7A = 0x7A7A
    GREASE_8A = 0x8A8A
    GREASE_9A = 0x9A9A
    GREASE_AA = 0xAAAA
    GREASE_BA = 0xBABA
    GREASE_CA = 0xCACA
    GREASE_DA = 0xDADA
    GREASE_EA = 0xEAEA
    GREASE_FA = 0xFAFA

    def __bytes__(self):
        return self.to_bytes(2)


@unique
class SignatureScheme(IntEnum):
    """https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1.3"""

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
