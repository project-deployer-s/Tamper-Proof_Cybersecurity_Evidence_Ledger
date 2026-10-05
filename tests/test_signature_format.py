import pytest

from cryptography.hazmat.primitives.asymmetric import utils

from security.signature_format import raw_ecdsa_to_der


def test_raw_ecdsa_to_der():
    r = 1
    s = 2

    raw_signature = (
        r.to_bytes(32, "big") +
        s.to_bytes(32, "big")
    )

    der_signature = raw_ecdsa_to_der(raw_signature)

    decoded_r, decoded_s = utils.decode_dss_signature(
        der_signature
    )

    assert decoded_r == r
    assert decoded_s == s


def test_invalid_raw_signature_length():
    with pytest.raises(ValueError):
        raw_ecdsa_to_der(b"too short")