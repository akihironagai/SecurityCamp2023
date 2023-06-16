from extension import Extension
from extension_type import ExtensionType
from signature_scheme import SignatureScheme
from variable import Variable


class SignatureAlgorithms(Extension):
    """Signature scheme list extension."""

    extension_type = ExtensionType.SIGNATURE_ALGORITHMS
    extension_data = Variable(
        data=bytes(
            Variable(
                data=[
                    bytes(SignatureScheme.RSA_PKCS1_SHA256),
                    bytes(SignatureScheme.RSA_PKCS1_SHA384),
                    bytes(SignatureScheme.RSA_PKCS1_SHA512),
                    bytes(SignatureScheme.ECDSA_SECP256R1_SHA256),
                    bytes(SignatureScheme.ECDSA_SECP384R1_SHA384),
                    bytes(SignatureScheme.ECDSA_SECP521R1_SHA512),
                    bytes(SignatureScheme.RSA_PSS_RSAE_SHA256),
                    bytes(SignatureScheme.RSA_PSS_RSAE_SHA384),
                    bytes(SignatureScheme.RSA_PSS_RSAE_SHA512),
                    bytes(SignatureScheme.ED25519),
                    bytes(SignatureScheme.ED448),
                    bytes(SignatureScheme.RSA_PSS_PSS_SHA256),
                    bytes(SignatureScheme.RSA_PSS_PSS_SHA384),
                    bytes(SignatureScheme.RSA_PSS_PSS_SHA512),
                ],
                length_field=2,
            )
        ),
        length_field=2,
    )
