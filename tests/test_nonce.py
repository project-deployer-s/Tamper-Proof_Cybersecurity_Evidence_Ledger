from datetime import datetime, timedelta, timezone

from security.nonce import is_nonce_reused, is_expired


def test_nonce_reused():
    used_nonces = {"abc123", "xyz789"}

    assert is_nonce_reused("abc123", used_nonces)


def test_nonce_not_reused():
    used_nonces = {"abc123", "xyz789"}

    assert not is_nonce_reused("new456", used_nonces)


def test_expired_timestamp():
    now = datetime.now(timezone.utc)

    old_timestamp = now - timedelta(seconds=120)

    assert is_expired(
        old_timestamp,
        max_age_seconds=60,
        now=now
    )


def test_valid_timestamp():
    now = datetime.now(timezone.utc)

    recent_timestamp = now - timedelta(seconds=30)

    assert not is_expired(
        recent_timestamp,
        max_age_seconds=60,
        now=now
    )