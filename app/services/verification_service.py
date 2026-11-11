
import base64
import binascii
import hashlib
from datetime import timezone
from pathlib import Path

from flask import current_app

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.extensions import db
from app.models import User, PublicKey, Message

from app.services.alert_service import create_alert
from app.services.ledger_service import append_ledger_event
from app.services.anchor_service import publish_and_update_outbox

from security.verification import verify_message
from security.verdicts import Verdict
from security.signature_format import raw_ecdsa_to_der


def verify_stored_message(
    message_id,
    actor_id,
    max_age_seconds=300
):

    try:
        # 1. Retrieve message
        message = db.session.get(Message, message_id)

        if not message:
            return None, "Message not found"

        # 2. Retrieve verifier
        actor_user = db.session.get(User, actor_id)

        if not actor_user:
            return None, "Verifier not found"

        # 3. Retrieve sender
        sender_user = db.session.get(
            User, message.sender_user_id
        )

        if not sender_user:
            return None, "Sender not found"

        # 4. Check verifier authorization
        receiver_user = User.query.filter_by(
            username=message.receiver
        ).first()

        is_sender = actor_user.id == message.sender_user_id

        is_receiver = (
            receiver_user is not None
            and actor_user.id == receiver_user.id
        )

        if not (is_sender or is_receiver):
            return None, "User is not authorized to verify this message"

        # 5. Validate sender identity
        sender_known = message.sender == sender_user.username

        # 6. Retrieve public key
        public_key_record = db.session.get(
            PublicKey, message.public_key_id
        )

        if not public_key_record:
            return None, "Public key not found"

        # 7. Retrieve previously used nonces
        used_nonces = {
            nonce
            for (nonce,) in db.session.query(Message.nonce)
            .filter(Message.id != message.id)
            .all()
        }

        # 8. Decode public key
        try:
            public_key_bytes = base64.b64decode(
                public_key_record.public_key,
                validate=True
            )

            public_key = serialization.load_der_public_key(
                public_key_bytes
            )

        except (
            ValueError,
            TypeError,
            binascii.Error,
            UnsupportedAlgorithm
        ):
            return None, "Invalid public key format"

        # 9. Validate ECDSA P-256 key
        if (
            public_key_record.algorithm != "ECDSA-P256"
            or not isinstance(
                public_key, ec.EllipticCurvePublicKey
            )
            or not isinstance(
                public_key.curve, ec.SECP256R1
            )
        ):
            return None, "Invalid ECDSA P-256 public key"

        # 10. Decode signature
        try:
            raw_signature = base64.b64decode(
                message.signature,
                validate=True
            )

            der_signature = raw_ecdsa_to_der(raw_signature)

        except (ValueError, TypeError, binascii.Error):
            return None, "Invalid signature format"

        # 11. Prepare timestamp
        timestamp_datetime = message.timestamp

        if timestamp_datetime.tzinfo is None:
            timestamp_datetime = timestamp_datetime.replace(
                tzinfo=timezone.utc
            )

        # 12. Retrieve attachment hashes
        attachment_hashes = sorted(
            attachment.sha256_hash
            for attachment in message.attachments
        )

        # 13. Run cryptographic verification
        verdict = verify_message(
            public_key=public_key,
            signature=der_signature,
            sender=message.sender,
            receiver=message.receiver,
            timestamp=message.timestamp_original,
            timestamp_datetime=timestamp_datetime,
            nonce=message.nonce,
            message=message.message,
            expected_content_hash=message.content_hash,
            sender_known=sender_known,
            used_nonces=used_nonces,
            max_age_seconds=max_age_seconds,
            key_revoked=public_key_record.is_revoked,
            attachment_hashes=attachment_hashes or None
        )

        # 14. Verify actual stored attachment files
                # 14. Verify actual stored attachment files
        if verdict == Verdict.GENUINE and message.attachments:

            upload_dir = (
                Path(current_app.instance_path) / "attachments"
            )

            for attachment in message.attachments:

                file_path = (
                    upload_dir / attachment.stored_filename
                )

                if not file_path.is_file():
                    verdict = Verdict.TAMPERED
                    break

                hasher = hashlib.sha256()

                with file_path.open("rb") as attachment_file:
                    for chunk in iter(
                        lambda: attachment_file.read(1024 * 1024),
                        b""
                    ):
                        hasher.update(chunk)

                actual_hash = hasher.hexdigest()

                if actual_hash != attachment.sha256_hash:
                    verdict = Verdict.TAMPERED
                    break

        # 15. Update verification status
        message.verification_status = verdict.value

        # 16. Create ledger event
        ledger_entry, error = append_ledger_event(
            "VERIFIED",
            message_id=message.id,
            actor_id=actor_user.id,
            detail={
                "verdict": verdict.value,
                "verified_by": actor_user.username
            },
            commit=False
        )

        if error or not ledger_entry:
            db.session.rollback()
            return None, error or "Failed to record verification event"

        # 17. Create alert for non-genuine messages
        alert = None

        if verdict != Verdict.GENUINE:

            alert, error = create_alert(
                ledger_seq=ledger_entry.seq,
                alert_type=verdict.value,
                severity="HIGH",
                commit=False
            )

            if error or not alert:
                db.session.rollback()
                return None, error or "Failed to create alert"

        # 18. Commit local changes
        db.session.commit()

        # 19. Publish external anchor
        success, anchor_error = publish_and_update_outbox(
            ledger_entry.seq,
            ledger_entry.entry_hash
        )

        if not success:
            print(
                "WARNING: External anchor publishing failed:",
                anchor_error
            )

        # 20. Return result
        return {
            "message_id": message.id,
            "verdict": verdict.value,
            "ledger_seq": ledger_entry.seq,
            "alert_id": alert.id if alert else None,
            "verified_by": actor_user.username,
            "verified_by_id": actor_user.id
        }, None

    except Exception:
        db.session.rollback()
        raise
