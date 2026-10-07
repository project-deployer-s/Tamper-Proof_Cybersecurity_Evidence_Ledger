import base64

from cryptography.hazmat.primitives import serialization

from security.ecdsa import verify_signature
from security.signature_format import raw_ecdsa_to_der


def test_browser_signature():
    payload = b'{"sender":"Alice","receiver":"Bob","timestamp":"2026-10-06T12:00:00Z","nonce":"abc123","message":"Hello Bob"}'

    public_key_base64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE50i7a7Dy1A9J2dp/1Cy6vHn8T4vjpnPTVnXqr9khjP6CmzzwBzMHiY4Lurya+qmDoAwVzZrqW92ZpLlb/ToVTg=="
    signature_base64 = "sIpVkcgakZfoWku0zpW17yk07V+lwlpxx04vYats3lxWH0RjtGKvIaDZsG1sjUeQh/Vg9uI+O2PaF2sqCXU0WA=="

    public_key = serialization.load_der_public_key(
        base64.b64decode(public_key_base64)
    )

    raw_signature = base64.b64decode(signature_base64)

    der_signature = raw_ecdsa_to_der(raw_signature)

    assert verify_signature(
        public_key,
        payload,
        der_signature
    )