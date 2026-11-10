
from datetime import datetime, timezone

from app.extensions import db
from app.models import User, PublicKey, Message


def store_message(
    sender_user_id,
    public_key_id,
    sender,
    receiver,
    timestamp,
    nonce,
    message,
    content_hash,
    signature
):
    """
    Validate and store a message.

    The caller is responsible for committing the transaction.
    This allows message, ledger and outbox records to be
    committed together.
    """

    try:
        # 1. Check sender
        user = db.session.get(User, sender_user_id)

        if not user:
            return None, "Sender not found"

        # 2. Check public key
        key = db.session.get(PublicKey, public_key_id)

        if not key or key.user_id != sender_user_id:
            return None, "Invalid public key"

        if key.is_revoked:
            return None, "Public key has been revoked"

        # 3. Validate required fields
        if not all([
            sender,
            receiver,
            timestamp,
            nonce,
            message,
            content_hash,
            signature
        ]):
            return None, "Required fields are missing"

        # 4. Validate timestamp type
        if not isinstance(timestamp, str):
            return None, "Timestamp must be a string"

        # Preserve the exact original timestamp
        timestamp_original = timestamp

        # 5. Convert timestamp for database storage
        try:
            parsed_timestamp = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )

        except (ValueError, TypeError):
            return None, "Invalid timestamp format"

        if parsed_timestamp.tzinfo is None:
            parsed_timestamp = parsed_timestamp.replace(
                tzinfo=timezone.utc
            )

        # 6. Create message record
        new_message = Message(
            sender_user_id=sender_user_id,
            public_key_id=public_key_id,
            sender=sender,
            receiver=receiver,
            timestamp=parsed_timestamp,
            timestamp_original=timestamp_original,
            nonce=nonce,
            message=message,
            content_hash=content_hash,
            signature=signature
        )

        db.session.add(new_message)

        # Flush generates the database ID without committing
        db.session.flush()

        return new_message, None

    except Exception as exc:
        db.session.rollback()

        print("MESSAGE STORAGE ERROR:", repr(exc))

        return None, "Failed to store message"
