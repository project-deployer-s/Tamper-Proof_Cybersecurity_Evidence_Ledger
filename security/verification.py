
from security.canonical import create_canonical_payload
from security.ecdsa import verify_signature
from security.hashing import calculate_sha256
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
    expected_content_hash: str,
    sender_known: bool,
    used_nonces: set[str],
    max_age_seconds: int,
    now=None,
    key_revoked: bool = False,
    attachment_hashes: list[str] | None = None,
) -> Verdict:

    # 1. Check sender
    if not sender_known:
        return Verdict.UNKNOWN_SENDER

    # 2. Check key status
    if key_revoked:
        return Verdict.REVOKED_KEY

    # 3. Check replay
    if is_nonce_reused(nonce, used_nonces):
        return Verdict.REPLAY

    # 4. Check expiry
    if is_expired(
        timestamp_datetime,
        max_age_seconds,
        now=now
    ):
        return Verdict.EXPIRED

    # 5. Recreate canonical payload
    canonical_payload = create_canonical_payload(
        sender=sender,
        receiver=receiver,
        timestamp=timestamp,
        nonce=nonce,
        message=message,
        attachment_hashes=attachment_hashes
    )

    # 6. Recalculate content hash
    actual_content_hash = calculate_sha256(canonical_payload)

    # 7. Detect content or attachment metadata tampering
    if actual_content_hash != expected_content_hash:
        return Verdict.TAMPERED

    # 8. Verify digital signature
    if not verify_signature(
        public_key,
        canonical_payload,
        signature
    ):
        return Verdict.INVALID_SIGNATURE

    # 9. Everything passed
    return Verdict.GENUINE
