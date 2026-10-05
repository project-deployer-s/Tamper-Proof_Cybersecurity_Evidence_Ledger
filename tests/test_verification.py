from datetime import datetime, timedelta, timezone

from security.ecdsa import generate_key_pair, sign_data
from security.canonical import create_canonical_payload
from security.verification import verify_message
from security.verdicts import Verdict


def get_recent_time():
    return datetime.now(timezone.utc)


def create_signed_message(private_key, message):
    timestamp = "2026-10-05T12:00:00Z"

    payload = create_canonical_payload(
        sender="Alice",
        receiver="Bob",
        timestamp=timestamp,
        nonce="nonce-1",
        message=message
    )

    signature = sign_data(private_key, payload)

    return timestamp, signature


def test_genuine_message():
    private_key, public_key = generate_key_pair()

    timestamp, signature = create_signed_message(
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
        nonce="nonce-1",
        message="Original Evidence",
        sender_known=True,
        used_nonces=set(),
        max_age_seconds=60,
        now=now
    )

    assert result == Verdict.GENUINE


def test_tampered_message_fails_signature():
    private_key, public_key = generate_key_pair()

    timestamp, signature = create_signed_message(
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
        nonce="nonce-1",
        message="Modified Evidence",
        sender_known=True,
        used_nonces=set(),
        max_age_seconds=60,
        now=now
    )

    assert result == Verdict.INVALID_SIGNATURE