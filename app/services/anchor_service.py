
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from dotenv import load_dotenv
from sqlalchemy import or_
from supabase import create_client
from supabase.lib.client_options import SyncClientOptions

from app.extensions import db
from app.models import AnchorOutbox


PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")


def get_supabase_client():
    """Create a Supabase client using private environment credentials."""

    url = os.getenv("SUPABASE_URL")
    secret_key = os.getenv("SUPABASE_SECRET_KEY")

    if not url or not secret_key:
        raise RuntimeError("Supabase credentials are missing")

    http_client = httpx.Client(
        timeout=httpx.Timeout(120.0),
        verify=True
    )

    options = SyncClientOptions(httpx_client=http_client)

    return create_client(url, secret_key, options=options)


def publish_anchor(seq: int, entry_hash: str):
    """Publish an immutable checkpoint and update the latest anchor."""

    client = None

    try:
        client = get_supabase_client()

        # 1. Check whether this historical checkpoint already exists
        existing = (
            client.table("ledger_anchor_history")
            .select("entry_hash")
            .eq("seq", seq)
            .execute()
        )

        if existing.data:
            if existing.data[0]["entry_hash"] != entry_hash:
                return False, "Anchor history hash conflict"

        else:
            # 2. Insert a new immutable checkpoint
            client.table("ledger_anchor_history").insert({
                "seq": seq,
                "entry_hash": entry_hash
            }).execute()

        # 3. Retrieve the latest external anchor
        latest = (
            client.table("ledger_anchor")
            .select("latest_seq, latest_hash")
            .eq("id", 1)
            .execute()
        )

        if latest.data:
            current = latest.data[0]

            # Do not overwrite a newer checkpoint
            if seq < current["latest_seq"]:
                return True, None

            # Check for conflicting hashes
            if seq == current["latest_seq"]:
                if entry_hash != current["latest_hash"]:
                    return False, "Latest anchor hash conflict"

                return True, None

        # 4. Update the latest checkpoint
        client.table("ledger_anchor").upsert(
            {
                "id": 1,
                "latest_seq": seq,
                "latest_hash": entry_hash
            },
            on_conflict="id"
        ).execute()

        return True, None

    except Exception as exc:
        print("ANCHOR PUBLISH ERROR:", repr(exc))
        return False, "Failed to publish external ledger anchor"


def get_external_anchor():
    """Retrieve the latest trusted external ledger anchor."""

    try:
        client = get_supabase_client()

        response = (
            client.table("ledger_anchor")
            .select("latest_seq, latest_hash, updated_at")
            .eq("id", 1)
            .execute()
        )

        if not response.data:
            return None, "External anchor not found"

        return response.data[0], None

    except Exception as exc:
        print("EXTERNAL ANCHOR RETRIEVAL ERROR:", repr(exc))
        return None, "Failed to retrieve external ledger anchor"


def get_anchor_history():
    """Retrieve all historical ledger checkpoints."""

    try:
        client = get_supabase_client()

        response = (
            client.table("ledger_anchor_history")
            .select("seq, entry_hash, anchored_at")
            .order("seq")
            .execute()
        )

        return response.data or [], None

    except Exception as exc:
        print("ANCHOR HISTORY ERROR:", repr(exc))
        return None, "Failed to retrieve anchor history"


def publish_and_update_outbox(seq: int, entry_hash: str):
    """
    Publish an anchor and update its local outbox status.

    If Supabase succeeds but the local database commit fails,
    a later retry can safely publish the same checkpoint again.
    """

    try:
        # 1. Find the corresponding outbox record
        outbox = AnchorOutbox.query.filter_by(
            ledger_seq=seq
        ).first()

        if outbox is None:
            return False, "Outbox record not found"

        # 2. Check that the supplied hash matches the outbox
        if outbox.entry_hash != entry_hash:
            return False, "Outbox hash mismatch"

        # 3. Publish to Supabase
        success, error = publish_anchor(seq, entry_hash)

        # 4. Update local outbox status
        if success:
            outbox.status = "PUBLISHED"
            outbox.last_error = None
            outbox.next_retry_at = None

        else:
            outbox.status = "PENDING"
            outbox.retry_count += 1
            outbox.last_error = error

            delay = min(2 ** outbox.retry_count, 3600)

            outbox.next_retry_at = (
                datetime.now(timezone.utc)
                + timedelta(seconds=delay)
            )

        # 5. Save the outbox update
        db.session.commit()

        return success, error

    except Exception as exc:
        db.session.rollback()

        print("OUTBOX UPDATE ERROR:", repr(exc))

        return False, "Failed to update anchor outbox"


def retry_pending_anchors(batch_size=50):
    """
    Retry pending Supabase anchors whose retry time has arrived.
    Each record is processed independently.
    """

    results = {
        "processed": 0,
        "published": 0,
        "failed": 0
    }

    if not isinstance(batch_size, int) or batch_size < 1:
        return {
            **results,
            "error": "Invalid batch size"
        }

    try:
        now = datetime.now(timezone.utc)

        # 1. Retrieve eligible pending records
        pending_records = (
            AnchorOutbox.query
            .filter(
                AnchorOutbox.status == "PENDING",
                or_(
                    AnchorOutbox.next_retry_at.is_(None),
                    AnchorOutbox.next_retry_at <= now
                )
            )
            .order_by(AnchorOutbox.ledger_seq.asc())
            .limit(batch_size)
            .all()
        )

        # 2. Process each record independently
        for record in pending_records:
            seq = record.ledger_seq
            entry_hash = record.entry_hash

            results["processed"] += 1

            try:
                success, error = publish_and_update_outbox(
                    seq,
                    entry_hash
                )

                if success:
                    results["published"] += 1
                else:
                    results["failed"] += 1

            except Exception as exc:
                db.session.rollback()

                print(
                    f"ANCHOR RETRY ERROR for sequence {seq}:",
                    repr(exc)
                )

                results["failed"] += 1

        return results

    except Exception as exc:
        db.session.rollback()

        print("RETRY PROCESS ERROR:", repr(exc))

        return {
            **results,
            "error": "Failed to process pending anchors"
        }
