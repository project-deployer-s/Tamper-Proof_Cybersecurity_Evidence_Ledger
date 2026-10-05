from datetime import datetime, timezone


def is_nonce_reused(nonce: str, used_nonces: set[str]) -> bool:
    """
    Check whether a nonce has already been used.
    """
    return nonce in used_nonces


def is_expired(
    timestamp: datetime,
    max_age_seconds: int,
    now: datetime | None = None
) -> bool:
    """
    Check whether a message is older than the allowed time window.

    max_age_seconds is supplied by the application because
    the project specification has not yet fixed the exact window.
    """

    if now is None:
        now = datetime.now(timezone.utc)

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    age = (now - timestamp).total_seconds()

    return age > max_age_seconds