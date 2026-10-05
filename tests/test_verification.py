from datetime import datetime, timedelta, timezone

from security.canonical import create_canonical_payload
from security.ecdsa import generate_key_pair, sign_data
from security.hashing import calculate_sha256
from security.verification import verify_message
from security.verdicts import Verdict


def get_recent_time():
    return datetime.now(timezone.utc)


def create_signed_message(private_key, message):
    timestamp = "2026-10-05T12:00:00Z"
    nonce = "nonce-1"

    payload = create_canonical_payload(
        sender="Alice",
        receiver="Bob",
        timestamp=timestamp,
        nonce=nonce,
        message=message
    )

    signature = sign_data(private_key, payload)
    content_hash = calculate_sha256(payload)

    return timestamp, nonce, signature, content_hash


def test_genuine_message():
    private_key, public_key = generate_key_pair()

    timestamp, nonce, signature, content_hash = create_signed_message(
        private_key,
        "Original Evidence"
    )

    now = get_recent_time()

    result = verify_message(
        public_key=public_key,
        signature=signature,
        sender="Alice",
        receiver="Bob",
        timestamp=timestamp,
        timestamp_datetime=now,
        nonce=nonce,
        message="Original Evidence",
        expected_content_hash=content_hash,
        sender_known=True,
        used_nonces=set(),
        max_age_seconds=60,
        now=now
    )

    assert result == Verdict.GENUINE


def test_tampered_message():
    private_key, public_key = generate_key_pair()

    timestamp, nonce, signature, content_hash = create_signed_message(
        private_key,
        "Original Evidence"
    )

    now = get_recent_time()

    result = verify_message(
        public_key=public_key,
        signature=signature,
        sender="Alice",
        receiver="Bob",
        timestamp=timestamp,
        timestamp_datetime=now,
        nonce=nonce,
        message="Modified Evidence",
        expected_content_hash=content_hash,
        sender_known=True,
        used_nonces=set(),
        max_age_seconds=60,
        now=now
    )

    assert result == Verdict.TAMPERED


def test_invalid_signature():
    private_key, public_key = generate_key_pair()

    timestamp, nonce, signature, content_hash = create_signed_message(
        private_key,
        "Original Evidence"
    )

    # Corrupt the signature while keeping the content unchanged.
    corrupted_signature = bytearray(signature)
    corrupted_signature[-1] ^= 1

    now = get_recent_time()

    result = verify_message(
        public_key=public_key,
        signature=bytes(corrupted_signature),
        sender="Alice",
        receiver="Bob",
        timestamp=timestamp,
        timestamp_datetime=now,
        nonce=nonce,
        message="Original Evidence",
        expected_content_hash=content_hash,
        sender_known=True,
        used_nonces=set(),
        max_age_seconds=60,
        now=now
    )

    assert result == Verdict.INVALID_SIGNATURE


def test_unknown_sender():
    private_key, public_key = generate_key_pair()

    timestamp, nonce, signature, content_hash = create_signed_message(
        private_key,
        "Original Evidence"
    )

    now = get_recent_time()

    result = verify_message(
        public_key=public_key,
        signature=signature,
        sender="Alice",
        receiver="Bob",
        timestamp=timestamp,
        timestamp_datetime=now,
        nonce=nonce,
        message="Original Evidence",
        expected_content_hash=content_hash,
        sender_known=False,
        used_nonces=set(),
        max_age_seconds=60,
        now=now
    )

    assert result == Verdict.UNKNOWN_SENDER


def test_revoked_key():
    private_key, public_key = generate_key_pair()

    timestamp, nonce, signature, content_hash = create_signed_message(
        private_key,
        "Original Evidence"
    )

    now = get_recent_time()

    result = verify_message(
        public_key=public_key,
        signature=signature,
        sender="Alice",
        receiver="Bob",
        timestamp=timestamp,
        timestamp_datetime=now,
        nonce=nonce,
        message="Original Evidence",
        expected_content_hash=content_hash,
        sender_known=True,
        key_revoked=True,
        used_nonces=set(),
        max_age_seconds=60,
        now=now
    )

    assert result == Verdict.REVOKED_KEY


def test_replay():
    private_key, public_key = generate_key_pair()

    timestamp, nonce, signature, content_hash = create_signed_message(
        private_key,
        "Original Evidence"
    )

    now = get_recent_time()

    result = verify_message(
        public_key=public_key,
        signature=signature,
        sender="Alice",
        receiver="Bob",
        timestamp=timestamp,
        timestamp_datetime=now,
        nonce=nonce,
        message="Original Evidence",
        expected_content_hash=content_hash,
        sender_known=True,
        used_nonces={nonce},
        max_age_seconds=60,
        now=now
    )

    assert result == Verdict.REPLAY


def test_expired():
    private_key, public_key = generate_key_pair()

    timestamp, nonce, signature, content_hash = create_signed_message(
        private_key,
        "Original Evidence"
    )

    now = get_recent_time()
    old_timestamp = now - timedelta(seconds=120)

    result = verify_message(
        public_key=public_key,
        signature=signature,
        sender="Alice",
        receiver="Bob",
        timestamp=timestamp,
        timestamp_datetime=old_timestamp,
        nonce=nonce,
        message="Original Evidence",
        expected_content_hash=content_hash,
        sender_known=True,
        used_nonces=set(),
        max_age_seconds=60,
        now=now
    )

    assert result == Verdict.EXPIRED