from enum import IntEnum


class CipherSuite(IntEnum):
    """Cipher suite enumeration."""

    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    TLS_AES_128_CCM_SHA256 = 0x1304
    TLS_AES_128_CCM_8_SHA256 = 0x1305

    def __bytes__(self):
        return self.value.to_bytes(2, "big")
