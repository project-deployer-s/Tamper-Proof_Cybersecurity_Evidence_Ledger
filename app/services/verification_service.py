
import base64
import binascii
from datetime import timezone

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.extensions import db
from app.models import User, PublicKey, Message

from app.services.alert_service import create_alert
from app.services.ledger_service import append_ledger_event
from app.services.anchor_service import publish_anchor

from security.verification import verify_message
from security.verdicts import Verdict
from security.signature_format import raw_ecdsa_to_der


def verify_stored_message(message_id, max_age_seconds=300):

    try:
        # 1. Retrieve the message
        message = db.session.get(Message, message_id)

        if not message:
            return None, "Message not found"

        # 2. Retrieve the sender
        sender_user = db.session.get(
            User, message.sender_user_id
        )

        if not sender_user:
            return None, "Sender not found"

        # 3. Validate sender identity
        sender_known = message.sender == sender_user.username

        # 4. Retrieve the public key
        public_key_record = db.session.get(
            PublicKey, message.public_key_id
        )

        if not public_key_record:
            return None, "Public key not found"

        # 5. Retrieve previously used nonces
        used_nonces = {
            nonce
            for (nonce,) in db.session.query(Message.nonce)
            .filter(Message.id != message.id)
            .all()
        }

        # 6. Decode and load the Base64 public key
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

        # 7. Validate the actual public key type and curve
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

        # 8. Decode the Base64 signature
        try:
            raw_signature = base64.b64decode(
                message.signature,
                validate=True
            )

            der_signature = raw_ecdsa_to_der(raw_signature)

        except (ValueError, TypeError, binascii.Error):
            return None, "Invalid signature format"

        # 9. Prepare timestamp
        timestamp_datetime = message.timestamp

        if timestamp_datetime.tzinfo is None:
            timestamp_datetime = timestamp_datetime.replace(
                tzinfo=timezone.utc
            )

        # 10. Run the security verification engine
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
            key_revoked=public_key_record.is_revoked
        )

        # 11. Update verification status
        message.verification_status = verdict.value

        # 12. Append ledger event without committing
        ledger_entry, error = append_ledger_event(
            "VERIFIED",
            message_id=message.id,
            actor_id=message.sender_user_id,
            detail={"verdict": verdict.value},
            commit=False
        )

        if error or not ledger_entry:
            db.session.rollback()
            return None, error or "Failed to record verification event"

        # 13. Create alert for non-genuine messages
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

        # 14. Commit all database changes together
        db.session.commit()

        # 15. Publish committed ledger hash to Supabase
        success, anchor_error = publish_anchor(
            ledger_entry.seq,
            ledger_entry.entry_hash
        )

        if not success:
            print(
                "WARNING: External anchor publishing failed:",
                anchor_error
            )

        # 16. Return verification result
        return {
            "message_id": message.id,
            "verdict": verdict.value,
            "ledger_seq": ledger_entry.seq,
            "alert_id": alert.id if alert else None
        }, None

    except Exception:
        db.session.rollback()
        raise
