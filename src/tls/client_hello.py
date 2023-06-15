import os

from cipher_suite import CipherSuite
from compression_method import CompressionMethod
from protocol_version import ProtocolVersion
from supported_versions import SupportedVersions
from variable import Variable


class ClientHello:
    """Client Hello message."""

    legacy_version = bytes(ProtocolVersion.TLS_1_2)
    random = os.urandom(32)
    legacy_session_id = Variable()
    cipher_suites = Variable(
        data=[
            bytes(CipherSuite.TLS_AES_128_GCM_SHA256),
            bytes(CipherSuite.TLS_AES_256_GCM_SHA384),
            bytes(CipherSuite.TLS_CHACHA20_POLY1305_SHA256),
            bytes(CipherSuite.TLS_AES_128_CCM_SHA256),
            bytes(CipherSuite.TLS_AES_128_CCM_8_SHA256),
        ],
        length_field=2,
    )
    legacy_compression_methods = Variable(
        data=bytes(CompressionMethod.NULL), length_field=1
    )
    # TODO: more extensions
    extension = Variable(
        data=[
            bytes(SupportedVersions()),
        ],
        length_field=2,
    )


print(bytes(SupportedVersions()).hex())
