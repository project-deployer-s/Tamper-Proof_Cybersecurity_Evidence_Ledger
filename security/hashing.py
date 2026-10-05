import hashlib


def calculate_sha256(data: bytes) -> str:
    """
    Calculate the SHA-256 hash of the given data.

    Args:
        data: Data to hash as bytes.

    Returns:
        SHA-256 hash as a hexadecimal string.
    """
    return hashlib.sha256(data).hexdigest()