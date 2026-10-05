from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


def raw_ecdsa_to_der(raw_signature: bytes) -> bytes:
    """
    Convert a WebCrypto ECDSA P-256 signature
    from raw r || s format to DER format.

    Raw signature:
        64 bytes
        ├── 32 bytes r
        └── 32 bytes s
    """

    if len(raw_signature) != 64:
        raise ValueError(
            "ECDSA P-256 raw signature must be exactly 64 bytes"
        )

    r = int.from_bytes(raw_signature[:32], byteorder="big")
    s = int.from_bytes(raw_signature[32:], byteorder="big")

    return encode_dss_signature(r, s)