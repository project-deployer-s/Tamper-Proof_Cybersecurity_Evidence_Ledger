import hashlib
import json

from app.services.anchor_service import publish_anchor, get_external_anchor
from app.extensions import db
from app.models import LedgerEntry


GENESIS_HASH = "0" * 64

ALLOWED_EVENTS = {
    "SENT",
    "VERIFIED",
    "KEY_REVOKED"
}

from datetime import timezone


def normalize_timestamp(value):
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc).isoformat()

def calculate_entry_hash(entry_data):
    """Calculate SHA-256 hash of a ledger entry."""

    canonical_data = json.dumps(
        entry_data,
        sort_keys=True,
        separators=(",", ":")
    )

    return hashlib.sha256(
        canonical_data.encode("utf-8")
    ).hexdigest()



def append_ledger_event(
    event_type,
    message_id=None,
    actor_id=None,
    detail=None,
    commit=True
):
    if event_type not in ALLOWED_EVENTS:
        return None, "Invalid event type"

    previous = (
        LedgerEntry.query
        .order_by(LedgerEntry.seq.desc())
        .first()
    )

    previous_hash = (
        previous.entry_hash if previous else GENESIS_HASH
    )

    entry = LedgerEntry(
        event_type=event_type,
        message_id=message_id,
        actor_id=actor_id,
        detail=detail or {},
        prev_hash=previous_hash,
        entry_hash="0" * 64
    )

    db.session.add(entry)
    db.session.flush()

    entry_data = {
        "seq": entry.seq,
        "event_type": entry.event_type,
        "message_id": entry.message_id,
        "actor_id": entry.actor_id,
        "detail": entry.detail,
        "prev_hash": entry.prev_hash,
        "created_at": normalize_timestamp(entry.created_at)
    }

    entry.entry_hash = calculate_entry_hash(entry_data)

    if commit:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            raise

        # Publish only after the database commit succeeds.
        success, error = publish_anchor(
            entry.seq,
            entry.entry_hash
        )

        if not success:
            return entry, (
                "Ledger entry committed, but external anchor "
                "publishing failed: " + str(error)
            )

    return entry, None


    # Create new ledger entry
    entry = LedgerEntry(
    event_type=event_type,
    message_id=message_id,
    actor_id=actor_id,
    detail=detail or {},
    prev_hash=previous_hash,
    entry_hash="0" * 64
)

    db.session.add(entry)

    # Generate sequence number
    db.session.flush()

    # Prepare data for hashing
    entry_data = {
        "seq": entry.seq,
        "event_type": entry.event_type,
        "message_id": entry.message_id,
        "actor_id": entry.actor_id,
        "detail": entry.detail,
        "prev_hash": entry.prev_hash,
        "created_at": normalize_timestamp(entry.created_at)
    }

    entry.entry_hash = calculate_entry_hash(entry_data)

    if commit:
        db.session.commit()

    return entry, None
def verify_ledger_integrity():
    # Step 1: Get all ledger entries in sequence order
    entries = LedgerEntry.query.order_by(LedgerEntry.seq.asc()).all()

    previous_hash = GENESIS_HASH

    # Step 2: Verify the local hash chain
    for entry in entries:

        if entry.prev_hash != previous_hash:
            return False, f"Broken link at entry {entry.seq}"

        entry_data = {
            "seq": entry.seq,
            "event_type": entry.event_type,
            "message_id": entry.message_id,
            "actor_id": entry.actor_id,
            "detail": entry.detail,
            "prev_hash": entry.prev_hash,
            "created_at": normalize_timestamp(entry.created_at)
        }

        calculated_hash = calculate_entry_hash(entry_data)

        if calculated_hash != entry.entry_hash:
            return False, f"Tampering detected at entry {entry.seq}"

        previous_hash = entry.entry_hash

    # Step 3: Retrieve the external anchor
    external_anchor, error = get_external_anchor()

    if error:
        if error == "External anchor not found":
            if not entries:
                return True, "Empty ledger; no external anchor exists"

            return False, "External anchor is missing"

        return False, "External anchor service unavailable"

    # Step 4: Check whether the local ledger is empty
    if not entries:
        return False, "External anchor exists but local ledger is empty"

    # Step 5: Compare local ledger with external anchor
    latest_entry = entries[-1]

    if external_anchor["latest_seq"] != latest_entry.seq:
        return False, "External anchor sequence mismatch"

    if external_anchor["latest_hash"] != latest_entry.entry_hash:
        return False, "External anchor hash mismatch"

    return True, "Local ledger and external anchor verified successfully"