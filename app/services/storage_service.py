
import hashlib

from app.services.anchor_service import get_supabase_client


BUCKET_NAME = "evidence-attachments"


def upload_file(storage_key, content, content_type):
    """Upload a file to private Supabase Storage."""

    client = get_supabase_client()

    response = (
        client.storage
        .from_(BUCKET_NAME)
        .upload(
            path=storage_key,
            file=content,
            file_options={
                "content-type": content_type,
                "upsert": "false"
            }
        )
    )

    return response


def download_file(storage_key):
    """Download a file from private Supabase Storage."""

    client = get_supabase_client()

    response = (
        client.storage
        .from_(BUCKET_NAME)
        .download(storage_key)
    )

    if response is None:
        raise FileNotFoundError("Attachment not found in storage")

    return response


def delete_file(storage_key):
    """Delete an uploaded file during rollback cleanup."""

    client = get_supabase_client()

    return (
        client.storage
        .from_(BUCKET_NAME)
        .remove([storage_key])
    )


def verify_file_hash(content, expected_hash):
    """Verify downloaded file content using SHA-256."""

    actual_hash = hashlib.sha256(content).hexdigest()

    return actual_hash == expected_hash
