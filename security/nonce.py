from datetime import datetime, timezone


def is_nonce_reused(nonce: str, used_nonces: set[str]) -> bool:
    """Check whether a nonce has already been used."""
    return nonce in used_nonces


def is_expired(
    timestamp: datetime,
    max_age_seconds: int,
    now: datetime | None = None
) -> bool:
    """Check whether a message is expired or has a future timestamp."""

    if now is None:
        now = datetime.now(timezone.utc)

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    age = (now - timestamp).total_seconds()

    return age < 0 or age > max_age_seconds