
from app.extensions import db
from app.models import User, PublicKey


def register_public_key(user_id, public_key, algorithm="ECDSA-P256"):
    """Register a public key for an existing user."""

    # 1. Check whether user exists
    user = db.session.get(User, user_id)

    if not user:
        return None, "User not found"

    # 2. Validate public key
    if not isinstance(public_key, str) or not public_key.strip():
        return None, "Public key is required"

    if algorithm != "ECDSA-P256":
        return None, "Unsupported algorithm"

    try:
        # 3. Create public key record
        key = PublicKey(
            user_id=user_id,
            public_key=public_key,
            algorithm=algorithm
        )

        db.session.add(key)
        db.session.commit()

        return key, None

    except Exception as exc:
        db.session.rollback()

        print("PUBLIC KEY REGISTRATION ERROR:", repr(exc))

        return None, "Failed to register public key"


def revoke_public_key(user_id, key_id):
    """Revoke a public key and record the event in the ledger."""

    # 1. Retrieve public key
    key = db.session.get(PublicKey, key_id)

    if not key:
        return None, "Public key not found"

    # 2. Verify ownership
    if key.user_id != user_id:
        return None, "Access forbidden"

    # 3. Check revocation status
    if key.is_revoked:
        return None, "Public key already revoked"

    try:
        from app.services.ledger_service import append_ledger_event
        from app.services.anchor_service import publish_and_update_outbox

        # 4. Revoke the key
        key.revoke()

        # 5. Create ledger event in the same transaction
        entry, error = append_ledger_event(
            event_type="KEY_REVOKED",
            actor_id=user_id,
            detail={
                "key_id": key.id,
                "algorithm": key.algorithm
            },
            commit=False
        )

        if error or not entry:
            db.session.rollback()
            return None, error or "Failed to create ledger event"

        # 6. Commit key revocation, ledger and outbox together
        db.session.commit()

    except Exception as exc:
        db.session.rollback()

        print("KEY REVOCATION ERROR:", repr(exc))

        return None, "Failed to revoke public key"

    # 7. Publish external anchor after successful commit
    try:
        success, anchor_error = publish_and_update_outbox(
            entry.seq,
            entry.entry_hash
        )

    except Exception as exc:
        success = False
        anchor_error = str(exc)

        print("KEY REVOCATION ANCHOR ERROR:", repr(exc))

    # 8. Return result
    return {
        "key_id": key.id,
        "is_revoked": key.is_revoked,
        "anchor_status": "published" if success else "pending"
    }, None
