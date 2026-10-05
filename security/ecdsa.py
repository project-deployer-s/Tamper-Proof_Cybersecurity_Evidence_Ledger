from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def generate_key_pair():
    """Generate an ECDSA P-256 private/public key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    return private_key, public_key


def sign_data(private_key, data: bytes) -> bytes:
    """Sign data using ECDSA P-256."""
    return private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )


def verify_signature(public_key, data: bytes, signature: bytes) -> bool:
    """Verify an ECDSA P-256 signature."""
    try:
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception:
        return False