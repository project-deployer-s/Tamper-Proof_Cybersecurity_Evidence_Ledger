from security.canonical import create_canonical_payload
from security.ecdsa import verify_signature
from security.verdicts import Verdict
from security.nonce import is_nonce_reused, is_expired


def verify_message(
    *,
    public_key,
    signature: bytes,
    sender: str,
    receiver: str,
    timestamp: str,
    timestamp_datetime,
    nonce: str,
    message: str,
    sender_known: bool,
    used_nonces: set[str],
    max_age_seconds: int,
    now=None,
    key_revoked: bool = False,
) -> Verdict:

    # 1. Check whether the sender is known
    if not sender_known:
        return Verdict.UNKNOWN_SENDER

    # 2. Check whether the key is revoked
    if key_revoked:
        return Verdict.REVOKED_KEY

    # 3. Check nonce replay
    if is_nonce_reused(nonce, used_nonces):
        return Verdict.REPLAY

    # 4. Check message expiry
    if is_expired(
        timestamp_datetime,
        max_age_seconds,
        now=now
    ):
        return Verdict.EXPIRED

    # 5. Recreate the exact canonical payload
    canonical_payload = create_canonical_payload(
        sender=sender,
        receiver=receiver,
        timestamp=timestamp,
        nonce=nonce,
        message=message
    )

    # 6. Verify the actual ECDSA signature
    if not verify_signature(
        public_key,
        canonical_payload,
        signature
    ):
        return Verdict.INVALID_SIGNATURE

    # 7. Everything passed
    return Verdict.GENUINE