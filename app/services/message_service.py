
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
    # Check sender
    user = db.session.get(User, sender_user_id)

    if not user:
        return None, "Sender not found"

    # Check public key
    key = db.session.get(PublicKey, public_key_id)

    if not key or key.user_id != sender_user_id:
        return None, "Invalid public key"

    if key.is_revoked:
        return None, "Public key has been revoked"

    # Check required fields
    if not all([
        sender, receiver, timestamp, nonce,
        message, content_hash, signature
    ]):
        return None, "Required fields are missing"

    # Preserve the exact original timestamp string
    if not isinstance(timestamp, str):
        return None, "Timestamp must be a string"

    timestamp_original = timestamp

    # Convert timestamp for database storage
    try:
        timestamp = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )
    except ValueError:
        return None, "Invalid timestamp format"

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    # Create message record
    new_message = Message(
        sender_user_id=sender_user_id,
        public_key_id=public_key_id,
        sender=sender,
        receiver=receiver,
        timestamp=timestamp,
        timestamp_original=timestamp_original,
        nonce=nonce,
        message=message,
        content_hash=content_hash,
        signature=signature
    )

    db.session.add(new_message)
    db.session.commit()

    return new_message, None
