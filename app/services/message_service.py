
from datetime import datetime, timezone

from app.extensions import db
from app.models import User, PublicKey, Message


# Message expiry bounds, expressed in seconds.
MIN_EXPIRY_SECONDS = 60
MAX_EXPIRY_SECONDS = 365 * 24 * 60 * 60


def store_message(
    sender_user_id,
    public_key_id,
    sender,
    receiver,
    timestamp,
    nonce,
    message,
    content_hash,
    signature,
    expiry_seconds=None
):
    """
    Validate and store a message.

    The caller is responsible for committing the transaction.
    This allows message, ledger and outbox records to be
    committed together.
    """

    try:
        # 1. Validate expiry duration.
        if expiry_seconds == "":
            expiry_seconds = None

        if expiry_seconds is not None:
            if isinstance(expiry_seconds, bool):
                return None, "Invalid expiry duration"

            if isinstance(expiry_seconds, str):
                if not expiry_seconds.isdigit():
                    return None, "Invalid expiry duration"
                expiry_seconds = int(expiry_seconds)
            elif not isinstance(expiry_seconds, int):
                return None, "Invalid expiry duration"

            if not MIN_EXPIRY_SECONDS <= expiry_seconds <= MAX_EXPIRY_SECONDS:
                return None, "Expiry must be between 1 minute and 365 days"

        # 2. Check sender.
        user = db.session.get(User, sender_user_id)

        if not user:
            return None, "Sender not found"

        # 3. Check public key.
        key = db.session.get(PublicKey, public_key_id)

        if not key or key.user_id != sender_user_id:
            return None, "Invalid public key"

        if key.is_revoked:
            return None, "Public key has been revoked"

        # 4. Validate required fields.
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

        # 5. Validate timestamp type.
        if not isinstance(timestamp, str):
            return None, "Timestamp must be a string"

        timestamp_original = timestamp

        # 6. Convert timestamp for database storage.
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

        # 7. Create message record.
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
            signature=signature,
            expiry_seconds=expiry_seconds
        )

        db.session.add(new_message)

        # Flush generates the database ID without committing.
        db.session.flush()

        return new_message, None

    except Exception:
        db.session.rollback()

        return None, "Failed to store message"
