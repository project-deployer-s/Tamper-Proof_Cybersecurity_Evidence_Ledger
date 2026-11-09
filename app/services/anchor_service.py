
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv
from supabase import create_client
from supabase.lib.client_options import SyncClientOptions


# Load environment variables from the project root
PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")


def get_supabase_client():
    """Create a Supabase client using private environment credentials."""

    url = os.getenv("SUPABASE_URL")
    secret_key = os.getenv("SUPABASE_SECRET_KEY")

    if not url or not secret_key:
        raise RuntimeError("Supabase credentials are missing")

    # Configure HTTP settings directly
    http_client = httpx.Client(
        timeout=httpx.Timeout(120.0),
        verify=True
    )

    options = SyncClientOptions(
        httpx_client=http_client
    )

    return create_client(
        url,
        secret_key,
        options=options
    )


def publish_anchor(seq: int, entry_hash: str):
    """Publish the latest ledger hash to the external anchor."""

    try:
        client = get_supabase_client()

        client.table("ledger_anchor").upsert(
            {
                "id": 1,
                "latest_seq": seq,
                "latest_hash": entry_hash
            },
            on_conflict="id"
        ).execute()

        return True, None

    except Exception:
        return False, "Failed to publish external ledger anchor"


def get_external_anchor():
    """Retrieve the trusted external ledger anchor."""

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

    except Exception:
        return None, "Failed to retrieve external ledger anchor"
