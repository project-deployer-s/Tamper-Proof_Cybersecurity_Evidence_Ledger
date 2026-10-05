from security.ecdsa import (
    generate_key_pair,
    sign_data,
    verify_signature
)


def test_ecdsa_sign_and_verify():
    private_key, public_key = generate_key_pair()

    data = b"Tamper-Proof Evidence"

    signature = sign_data(private_key, data)

    assert verify_signature(public_key, data, signature)


def test_tampered_data_fails():
    private_key, public_key = generate_key_pair()

    data = b"Original Evidence"
    tampered_data = b"Modified Evidence"

    signature = sign_data(private_key, data)

    assert not verify_signature(
        public_key,
        tampered_data,
        signature
    )