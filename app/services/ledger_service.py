
import hashlib
import json
from datetime import timezone

from app.extensions import db
from app.models import LedgerEntry, AnchorOutbox

from app.services.anchor_service import (
    publish_and_update_outbox,
    get_external_anchor,
    get_anchor_history
)


GENESIS_HASH = "0" * 64

ALLOWED_EVENTS = {
    "SENT",
    "VERIFIED",
    "KEY_REVOKED"
}


def normalize_timestamp(value):
    """Normalize timestamps to UTC ISO format."""
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
    """
    Append a new event to the local hash-chain ledger.

    The ledger entry and its outbox record are created
    in the same database transaction.
    """

    if event_type not in ALLOWED_EVENTS:
        return None, "Invalid event type"

    try:
        # 1. Get the previous ledger entry
        previous = (
            LedgerEntry.query
            .order_by(LedgerEntry.seq.desc())
            .first()
        )

        previous_hash = (
            previous.entry_hash if previous else GENESIS_HASH
        )

        # 2. Create the new ledger entry
        entry = LedgerEntry(
            event_type=event_type,
            message_id=message_id,
            actor_id=actor_id,
            detail=detail or {},
            prev_hash=previous_hash,
            entry_hash="0" * 64
        )

        db.session.add(entry)

        # Generate the sequence number
        db.session.flush()

        # 3. Prepare canonical entry data
        entry_data = {
            "seq": entry.seq,
            "event_type": entry.event_type,
            "message_id": entry.message_id,
            "actor_id": entry.actor_id,
            "detail": entry.detail,
            "prev_hash": entry.prev_hash,
            "created_at": normalize_timestamp(entry.created_at)
        }

        # 4. Calculate the entry hash
        entry.entry_hash = calculate_entry_hash(entry_data)

        # 5. Create the external anchoring outbox record
        outbox_entry = AnchorOutbox(
            ledger_seq=entry.seq,
            entry_hash=entry.entry_hash,
            status="PENDING",
            retry_count=0
        )

        db.session.add(outbox_entry)

        # 6. Commit both records atomically when requested
        if commit:
            db.session.commit()

    except Exception:
        db.session.rollback()
        raise

    # 7. Publish only after the database transaction commits
    if commit:
        try:
            success, error = publish_and_update_outbox(
                entry.seq,
                entry.entry_hash
            )

            if not success:
                return entry, (
                    "Ledger entry committed, but external "
                    "anchor publishing failed: " + str(error)
                )

        except Exception as error:
            # The local ledger and outbox are already committed.
            # The retry mechanism can process the pending record.
            return entry, (
                "Ledger entry committed, but external "
                "anchor publishing encountered an error: "
                + str(error)
            )

    return entry, None


def verify_ledger_integrity():
    """
    Verify the local hash chain and external Supabase checkpoints.
    """

    try:
        # 1. Retrieve local ledger entries
        entries = (
            LedgerEntry.query
            .order_by(LedgerEntry.seq.asc())
            .all()
        )

        # 2. Verify the local hash chain
        previous_hash = GENESIS_HASH

        for entry in entries:

            if entry.prev_hash != previous_hash:
                return False, (
                    f"Broken link at entry {entry.seq}"
                )

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
                return False, (
                    f"Tampering detected at entry {entry.seq}"
                )

            previous_hash = entry.entry_hash

        # 3. Retrieve historical external anchors
        anchors, error = get_anchor_history()

        if error:
            return False, "External anchor history unavailable"

        # 4. Handle empty ledger conditions
        if not entries and not anchors:
            return True, "Empty ledger; no external anchors exist"

        if not anchors:
            return False, "External anchor history is missing"

        if not entries:
            return False, (
                "External anchors exist but local ledger is empty"
            )

        # 5. Compare historical checkpoints
        local_entries = {
            entry.seq: entry.entry_hash
            for entry in entries
        }

        for anchor in anchors:

            seq = anchor["seq"]
            anchored_hash = anchor["entry_hash"]

            if seq not in local_entries:
                return False, (
                    f"Anchored entry {seq} is missing locally"
                )

            if local_entries[seq] != anchored_hash:
                return False, (
                    f"External anchor mismatch at entry {seq}"
                )

        # 6. Verify the latest external anchor
        external_anchor, error = get_external_anchor()

        if not external_anchor:
            if error == "External anchor not found":
                return False, "External anchor is missing"

            return False, "External anchor service unavailable"

        if error:
            return False, "External anchor service unavailable"

        latest_entry = entries[-1]

        if external_anchor["latest_seq"] != latest_entry.seq:
            return False, "External anchor sequence mismatch"

        if external_anchor["latest_hash"] != latest_entry.entry_hash:
            return False, "External anchor hash mismatch"

        return True, (
            "Local ledger and all historical anchors "
            "verified successfully"
        )

    except Exception:
        return False, "Unexpected error during ledger integrity verification"
