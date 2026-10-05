from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


def raw_ecdsa_to_der(raw_signature: bytes) -> bytes:
    """
    Convert a WebCrypto ECDSA P-256 signature from
    raw r || s format into DER format.

    WebCrypto P-256 signature:
        64 bytes = 32-byte r + 32-byte s
    """

    if len(raw_signature) != 64:
        raise ValueError(
            "ECDSA P-256 raw signature must be exactly 64 bytes"
        )

    r = int.from_bytes(raw_signature[:32], byteorder="big")
    s = int.from_bytes(raw_signature[32:], byteorder="big")

    return encode_dss_signature(r, s)