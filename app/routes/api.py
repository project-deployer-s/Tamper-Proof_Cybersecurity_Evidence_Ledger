import base64
import binascii

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from security.canonical import create_canonical_payload
from security.hashing import calculate_sha256
from security.signature_format import raw_ecdsa_to_der
from security.ecdsa import verify_signature
import hashlib
import json
from io import BytesIO

from flask import Blueprint, request, jsonify, send_file, current_app
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity
)

from app.services.demo_service import (
    simulate_attack,
    simulate_ledger_tampering,
    ATTACKS
)

from app.extensions import db
from app.models import (
    User,
    Message,
    MessageAttachment,
    PublicKey,
    LedgerEntry,
    Alert
)

from app.services.user_service import register_user
from app.services.key_service import (
    register_public_key,
    revoke_public_key
)
from app.services.message_service import store_message
from app.services.attachment_service import save_attachment
from app.services.storage_service import delete_file, download_file

from app.services.ledger_service import (
    append_ledger_event,
    verify_ledger_integrity
)
from app.services.verification_service import verify_stored_message
from app.services.anchor_service import publish_and_update_outbox


api_bp = Blueprint("api", __name__, url_prefix="/api")



def get_current_user():
    """Return the authenticated user from the database."""
    identity = get_jwt_identity()

    if identity is None:
        return None

    try:
        user_id = int(identity)
    except (TypeError, ValueError):
        return None

    return db.session.get(User, user_id)


def admin_required():
    """Return an error response unless the authenticated user is an admin."""
    current_user = get_current_user()

    if not current_user:
        return None, (jsonify({"error": "User not found"}), 404)

    if current_user.role != "admin":
        return None, (jsonify({"error": "Admin access required"}), 403)

    return current_user, None



def serialize_message(message):
    expired = message.is_expired

    return {
        "id": message.id,
        "sender": message.sender,
        "receiver": message.receiver,

        # Never expose expired message content through the API.
        "message": None if expired else message.message,

        "timestamp": message.timestamp_original,
        "nonce": message.nonce,
        "content_hash": message.content_hash,
        "signature": message.signature,
        "public_key_id": message.public_key_id,
        "verification_status": message.verification_status,
        "created_at": message.created_at.isoformat(),

        "expiry_seconds": message.expiry_seconds,
        "expires_at": (
            message.expires_at.isoformat()
            if message.expires_at else None
        ),
        "is_expired": expired,

        "attachments": [
            {
                "id": attachment.id,
                "filename": attachment.original_filename,
                "mime_type": attachment.mime_type,
                "file_size": attachment.file_size,
                "sha256_hash": attachment.sha256_hash,

                # Do not provide download URLs for expired messages.
                "download_url": (
                    None if expired else
                    f"/api/messages/{message.id}/attachments/"
                    f"{attachment.id}"
                )
            }
            for attachment in message.attachments
        ]
    }



# -----------------------------------------
# 1. USER REGISTRATION
# -----------------------------------------

@api_bp.route("/users", methods=["POST"])
def create_user():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not all([username, email, password]):
        return jsonify({
            "error": "Username, email and password are required"
        }), 400

    if not isinstance(password, str) or len(password) < 8:
        return jsonify({
            "error": "Password must contain at least 8 characters"
        }), 400

    user, error = register_user(username, email, password)

    if error:
        return jsonify({"error": error}), 409

    return jsonify({
        "message": "User registered successfully",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email
        }
    }), 201


# -----------------------------------------
# 2. USER LOGIN
# -----------------------------------------

@api_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({
            "error": "Email and password are required"
        }), 400

    user = User.query.filter_by(email=email).first()

    if not user or not user.check_password(password):
        return jsonify({
            "error": "Invalid email or password"
        }), 401

    token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role}
    )

    return jsonify({
        "message": "Login successful",
        "access_token": token,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role
        }
    }), 200


# -----------------------------------------
# 3. LIST USERS
# -----------------------------------------

@api_bp.route("/users", methods=["GET"])
@jwt_required()
def list_users():
    current_user = get_current_user()

    if not current_user:
        return jsonify({"error": "User not found"}), 404

    users = User.query.filter(
        User.id != current_user.id
    ).order_by(User.username.asc()).all()

    return jsonify({
        "users": [
            {
                "id": user.id,
                "username": user.username
            }
            for user in users
        ]
    }), 200


# -----------------------------------------
# 4. PUBLIC KEY MANAGEMENT
# -----------------------------------------

@api_bp.route("/users/<int:user_id>/keys", methods=["POST"])
@jwt_required()
def create_public_key(user_id):
    if int(get_jwt_identity()) != user_id:
        return jsonify({"error": "Access forbidden"}), 403

    data = request.get_json(silent=True) or {}

    public_key = data.get("public_key")
    algorithm = data.get("algorithm", "ECDSA-P256")

    if not public_key:
        return jsonify({"error": "Public key is required"}), 400

    key, error = register_public_key(
        user_id,
        public_key,
        algorithm
    )

    if error:
        status = 404 if error == "User not found" else 400
        return jsonify({"error": error}), status

    return jsonify({
        "message": "Public key registered successfully",
        "key": {
            "id": key.id,
            "user_id": key.user_id,
            "algorithm": key.algorithm,
            "is_revoked": key.is_revoked
        }
    }), 201


@api_bp.route("/users/<int:user_id>/keys", methods=["GET"])
@jwt_required()
def get_user_keys(user_id):
    if int(get_jwt_identity()) != user_id:
        return jsonify({"error": "Access forbidden"}), 403

    keys = PublicKey.query.filter_by(
        user_id=user_id
    ).order_by(PublicKey.created_at.desc()).all()

    return jsonify({
        "keys": [
            {
                "id": key.id,
                "public_key": key.public_key,
                "algorithm": key.algorithm,
                "is_revoked": key.is_revoked,
                "created_at": key.created_at.isoformat(),
                "revoked_at": (
                    key.revoked_at.isoformat()
                    if key.revoked_at else None
                )
            }
            for key in keys
        ]
    }), 200


@api_bp.route(
    "/users/<int:user_id>/keys/<int:key_id>/revoke",
    methods=["POST"]
)
@jwt_required()
def revoke_key(user_id, key_id):
    if int(get_jwt_identity()) != user_id:
        return jsonify({"error": "Access forbidden"}), 403

    result, error = revoke_public_key(user_id, key_id)

    if error:
        status = 404 if error == "Public key not found" else 400
        return jsonify({"error": error}), status

    return jsonify({
        "message": "Public key revoked successfully",
        "data": result
    }), 200


# -----------------------------------------
# 5. SEND MESSAGE
# -----------------------------------------



@api_bp.route("/messages", methods=["POST"])
@jwt_required()
def submit_message():
    current_user = get_current_user()

    if not current_user:
        return jsonify({"error": "User not found"}), 404

    saved_attachments = []

    def cleanup_saved_files():
        for attachment in saved_attachments:
            try:
                delete_file(attachment.stored_filename)
            except Exception:
                current_app.logger.exception(
                    "Failed to remove orphaned Supabase attachment"
                )

    if request.mimetype == "multipart/form-data":
        data = request.form.to_dict()
        uploaded_files = request.files.getlist("attachments")
    else:
        data = request.get_json(silent=True) or {}
        uploaded_files = []

    required = [
        "public_key_id",
        "sender",
        "receiver",
        "timestamp",
        "nonce",
        "message",
        "content_hash",
        "signature"
    ]

    if not all(data.get(field) is not None for field in required):
        return jsonify({"error": "Required fields are missing"}), 400

    if data["sender"] != current_user.username:
        return jsonify({"error": "Invalid sender identity"}), 403

    receiver = User.query.filter_by(
        username=data["receiver"]
    ).first()

    if not receiver:
        return jsonify({"error": "Receiver not found"}), 404

    try:
        key_id = int(data["public_key_id"])

        attachment_hashes = json.loads(
            data.get("attachment_hashes", "[]")
        )

        if not isinstance(attachment_hashes, list):
            raise ValueError("Invalid attachment hashes")

        if len(attachment_hashes) != len(uploaded_files):
            return jsonify({
                "error": "Attachment hash count does not match uploaded files"
            }), 400

        if any(
            not isinstance(value, str)
            or len(value) != 64
            or any(c not in "0123456789abcdef" for c in value)
            for value in attachment_hashes
        ):
            return jsonify({"error": "Invalid attachment hash"}), 400

        # Validate expiry duration.
        expiry_raw = data.get("expiry_seconds", "")

        if expiry_raw == "":
            expiry_seconds = None
        else:
            if (
                not isinstance(expiry_raw, str)
                or not expiry_raw.isdigit()
            ):
                return jsonify({
                    "error": "Invalid expiry duration"
                }), 400

            expiry_seconds = int(expiry_raw)

            if not 60 <= expiry_seconds <= 365 * 24 * 60 * 60:
                return jsonify({
                    "error": "Expiry must be between 1 minute and 365 days"
                }), 400

        # Retrieve sender's public key.
        public_key_record = db.session.get(PublicKey, key_id)

        if (
            not public_key_record
            or public_key_record.user_id != current_user.id
            or public_key_record.is_revoked
            or public_key_record.algorithm != "ECDSA-P256"
        ):
            return jsonify({
                "error": "Invalid or revoked signing key"
            }), 400

        public_key_bytes = base64.b64decode(
            public_key_record.public_key,
            validate=True
        )

        public_key = serialization.load_der_public_key(
            public_key_bytes
        )

        if (
            not isinstance(public_key, ec.EllipticCurvePublicKey)
            or not isinstance(public_key.curve, ec.SECP256R1)
        ):
            return jsonify({
                "error": "Invalid ECDSA P-256 public key"
            }), 400

        # Recreate exactly the payload signed by the browser.
        canonical_payload = create_canonical_payload(
            sender=current_user.username,
            receiver=receiver.username,
            timestamp=data["timestamp"],
            nonce=data["nonce"],
            message=data["message"],
            attachment_hashes=attachment_hashes or None,
            expiry_seconds=expiry_seconds
        )

        calculated_hash = calculate_sha256(canonical_payload)

        if calculated_hash != data["content_hash"]:
            return jsonify({
                "error": "Message content hash mismatch"
            }), 400

        raw_signature = base64.b64decode(
            data["signature"],
            validate=True
        )

        der_signature = raw_ecdsa_to_der(raw_signature)

        if not verify_signature(
            public_key,
            canonical_payload,
            der_signature
        ):
            return jsonify({
                "error": "Message signature verification failed"
            }), 400

        # Store the message only after signature verification.
        message, error = store_message(
            sender_user_id=current_user.id,
            public_key_id=key_id,
            sender=current_user.username,
            receiver=receiver.username,
            timestamp=data["timestamp"],
            nonce=data["nonce"],
            message=data["message"],
            content_hash=data["content_hash"],
            signature=data["signature"],
            expiry_seconds=expiry_seconds
        )

        if error:
            db.session.rollback()
            return jsonify({"error": error}), 400

        # Save attachments.
        for uploaded_file in uploaded_files:
            attachment, error = save_attachment(
                uploaded_file,
                message.id
            )

            if error:
                db.session.rollback()
                cleanup_saved_files()
                return jsonify({"error": error}), 400

            saved_attachments.append(attachment)

        actual_hashes = sorted(
            attachment.sha256_hash
            for attachment in saved_attachments
        )

        if actual_hashes != sorted(attachment_hashes):
            db.session.rollback()
            cleanup_saved_files()
            return jsonify({
                "error": "Attachment integrity hash mismatch"
            }), 400

        # Record signed expiry information in the ledger.
        entry, error = append_ledger_event(
            event_type="SENT",
            message_id=message.id,
            actor_id=current_user.id,
            detail={
                "sender": message.sender,
                "receiver": message.receiver,
                "content_hash": message.content_hash,
                "attachment_hashes": actual_hashes,
                "expiry_seconds": expiry_seconds
            },
            commit=False
        )

        if error:
            db.session.rollback()
            cleanup_saved_files()
            return jsonify({"error": error}), 500

        db.session.commit()

    except (
        ValueError,
        TypeError,
        binascii.Error,
        UnsupportedAlgorithm
    ):
        db.session.rollback()
        cleanup_saved_files()
        return jsonify({
            "error": "Invalid message or cryptographic data"
        }), 400

    except Exception:
        db.session.rollback()
        cleanup_saved_files()
        current_app.logger.exception("Message submission failed")
        return jsonify({
            "error": "Message submission failed"
        }), 500

    try:
        success, anchor_error = publish_and_update_outbox(
            entry.seq,
            entry.entry_hash
        )
    except Exception:
        success = False

    return jsonify({
        "message": "Message submitted successfully",
        "data": serialize_message(message),
        "ledger_seq": entry.seq,
        "anchor_status": "published" if success else "pending"
    }), 201




# -----------------------------------------
# 6. INBOX
# -----------------------------------------

@api_bp.route("/messages/inbox", methods=["GET"])
@jwt_required()
def get_inbox():
    current_user = get_current_user()

    if not current_user:
        return jsonify({"error": "User not found"}), 404

    messages = Message.query.filter_by(
        receiver=current_user.username
    ).order_by(Message.created_at.desc()).all()

    return jsonify({
        "messages": [
            serialize_message(message)
            for message in messages
        ]
    }), 200


# -----------------------------------------
# 7. SENT MESSAGES
# -----------------------------------------

@api_bp.route("/messages/sent", methods=["GET"])
@jwt_required()
def get_sent_messages():
    current_user = get_current_user()

    if not current_user:
        return jsonify({"error": "User not found"}), 404

    messages = Message.query.filter_by(
        sender_user_id=current_user.id
    ).order_by(Message.created_at.desc()).all()

    return jsonify({
        "messages": [
            serialize_message(message)
            for message in messages
        ]
    }), 200


# -----------------------------------------
# 8. MESSAGE VERIFICATION
# -----------------------------------------

@api_bp.route("/messages/<int:message_id>/verify", methods=["POST"])
@jwt_required()
def verify_message_api(message_id):
    current_user = get_current_user()

    if not current_user:
        return jsonify({"error": "User not found"}), 404

    message = db.session.get(Message, message_id)

    if not message:
        return jsonify({"error": "Message not found"}), 404

    # Only the sender or intended receiver can verify.
    if (
        message.sender_user_id != current_user.id
        and message.receiver != current_user.username
    ):
        return jsonify({"error": "Access forbidden"}), 403

    try:
        result, error = verify_stored_message(
            message_id=message_id,
            actor_id=current_user.id
        )

        if error:
            return jsonify({"error": error}), 400

        return jsonify({
            "message": "Verification completed",
            "data": result
        }), 200

    except Exception:
        db.session.rollback()
        return jsonify({
            "error": "Message verification failed"
        }), 500



# -----------------------------------------
# 9. LEDGER HISTORY
# -----------------------------------------

@api_bp.route("/ledger", methods=["GET"])
@jwt_required()
def get_ledger():
    entries = LedgerEntry.query.order_by(
        LedgerEntry.seq.desc()
    ).all()

    # Fetch related messages in one query. Verification events may not
    # contain sender/receiver in their detail JSON, even though the
    # original message still has those values.
    message_ids = {
        entry.message_id
        for entry in entries
        if entry.message_id is not None
    }

    messages_by_id = {}
    if message_ids:
        related_messages = Message.query.filter(
            Message.id.in_(message_ids)
        ).all()
        messages_by_id = {
            message.id: message
            for message in related_messages
        }

    serialized_entries = []

    for entry in entries:
        detail = entry.detail
        if not isinstance(detail, dict):
            detail = {}

        message = messages_by_id.get(entry.message_id)

        # Prefer the original message record. Fall back to values already
        # recorded in the immutable ledger event for legacy/deleted records.
        sender = (
            message.sender if message else detail.get("sender")
        )
        receiver = (
            message.receiver if message else detail.get("receiver")
        )

        # Enrich the API response only; do not alter the stored ledger detail
        # or recompute historical ledger hashes.
        response_detail = dict(detail)
        if sender is not None:
            response_detail.setdefault("sender", sender)
        if receiver is not None:
            response_detail.setdefault("receiver", receiver)

        serialized_entries.append({
            "seq": entry.seq,
            "event_type": entry.event_type,
            "message_id": entry.message_id,
            "actor_id": entry.actor_id,
            "sender": sender,
            "receiver": receiver,
            "detail": response_detail,
            "prev_hash": entry.prev_hash,
            "entry_hash": entry.entry_hash,
            "created_at": entry.created_at.isoformat()
        })

    return jsonify({
        "entries": serialized_entries
    }), 200


# -----------------------------------------
# 10. SECURITY ALERTS
# -----------------------------------------

@api_bp.route("/alerts", methods=["GET"])
@jwt_required()
def get_alerts():
    current_user, error_response = admin_required()

    if error_response:
        return error_response

    alerts = Alert.query.order_by(
        Alert.created_at.desc()
    ).all()

    return jsonify({
        "alerts": [
            {
                "id": alert.id,
                "ledger_seq": alert.ledger_seq,
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "acknowledged": alert.acknowledged,
                "created_at": alert.created_at.isoformat()
            }
            for alert in alerts
        ]
    }), 200


# -----------------------------------------
# 11. LEDGER INTEGRITY VERIFICATION
# -----------------------------------------

@api_bp.route("/ledger/verify", methods=["GET"])
@jwt_required()
def verify_ledger():
    valid, result = verify_ledger_integrity()

    return jsonify({
        "integrity": "VALID" if valid else "TAMPERED",
        "message": result
    }), 200 if valid else 409

# -----------------------------------------
# 12. SAFE ATTACK SIMULATIONS
# -----------------------------------------

@api_bp.route("/demo/attacks", methods=["GET"])
@jwt_required()
def get_demo_attacks():
    current_user, error_response = admin_required()
    if error_response:
        return error_response

    return jsonify({
        "attacks": [
            {
                "id": attack_id,
                **details
            }
            for attack_id, details in ATTACKS.items()
        ]
    }), 200


@api_bp.route("/demo/attacks/<attack_type>", methods=["POST"])
@jwt_required()
def run_demo_attack(attack_type):
    current_user, error_response = admin_required()
    if error_response:
        return error_response

    result, error = simulate_attack(attack_type)

    if error:
        return jsonify({"error": error}), 400

    return jsonify({
        "result": result
    }), 200

# -----------------------------------------
# 13. LEDGER TAMPERING SIMULATION
# -----------------------------------------

@api_bp.route("/demo/ledger-tampering", methods=["POST"])
@jwt_required()
def demo_ledger_tampering():
    current_user, error_response = admin_required()
    if error_response:
        return error_response

    try:
        result = simulate_ledger_tampering()

        return jsonify({
            "message": "Ledger tampering simulation completed",
            "result": result
        }), 200

    except Exception:
        return jsonify({
            "error": "Ledger tampering simulation failed"
        }), 500

# -----------------------------------------
# 14. SECURE ATTACHMENT DOWNLOAD
# -----------------------------------------


@api_bp.route(
    "/messages/<int:message_id>/attachments/<int:attachment_id>",
    methods=["GET"]
)
@jwt_required()
def download_attachment(message_id, attachment_id):

    current_user = get_current_user()

    if not current_user:
        return jsonify({"error": "User not found"}), 404

    # Retrieve message and attachment.
    message = db.session.get(Message, message_id)
    attachment = db.session.get(
        MessageAttachment, attachment_id
    )

    if not message or not attachment:
        return jsonify({"error": "Attachment not found"}), 404

    if attachment.message_id != message.id:
        return jsonify({"error": "Attachment not found"}), 404

    # Allow only the sender or receiver.
    receiver = User.query.filter_by(
        username=message.receiver
    ).first()

    is_sender = current_user.id == message.sender_user_id
    is_receiver = (
        receiver is not None
        and current_user.id == receiver.id
    )

    if not (is_sender or is_receiver):
        return jsonify({"error": "Access forbidden"}), 403

    # Block attachment downloads after message expiry.
    if message.is_expired:
        return jsonify({
            "error": "Message has expired. Attachment is no longer available."
        }), 410

    # Download the object from private Supabase Storage.
    try:
        file_content = download_file(attachment.stored_filename)

    except FileNotFoundError:
        return jsonify({"error": "Stored attachment not found"}), 404

    except Exception:
        current_app.logger.exception(
            "Failed to download attachment from Supabase Storage"
        )
        return jsonify({
            "error": "Attachment storage is unavailable"
        }), 502

    # Verify SHA-256 integrity before download.
    actual_hash = hashlib.sha256(file_content).hexdigest()

    if actual_hash != attachment.sha256_hash:
        current_app.logger.error(
            "Attachment integrity check failed for attachment ID %s",
            attachment.id
        )
        return jsonify({
            "error": "Attachment integrity check failed"
        }), 409

    return send_file(
        BytesIO(file_content),
        mimetype=attachment.mime_type,
        as_attachment=True,
        download_name=attachment.original_filename
    )
