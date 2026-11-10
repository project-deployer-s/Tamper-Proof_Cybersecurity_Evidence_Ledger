from flask import Blueprint, request, jsonify
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
from app.models import User, Message, PublicKey, LedgerEntry, Alert

from app.services.user_service import register_user
from app.services.key_service import (
    register_public_key,
    revoke_public_key
)
from app.services.message_service import store_message
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
    return {
        "id": message.id,
        "sender": message.sender,
        "receiver": message.receiver,
        "message": message.message,
        "timestamp": message.timestamp_original,
        "content_hash": message.content_hash,
        "signature": message.signature,
        "public_key_id": message.public_key_id,
        "verification_status": message.verification_status,
        "created_at": message.created_at.isoformat()
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

    data = request.get_json(silent=True) or {}

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
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid public key ID"}), 400

    try:
        message, error = store_message(
            sender_user_id=current_user.id,
            public_key_id=key_id,
            sender=current_user.username,
            receiver=receiver.username,
            timestamp=data["timestamp"],
            nonce=data["nonce"],
            message=data["message"],
            content_hash=data["content_hash"],
            signature=data["signature"]
        )

        if error:
            db.session.rollback()
            return jsonify({"error": error}), 400

        entry, error = append_ledger_event(
            event_type="SENT",
            message_id=message.id,
            actor_id=current_user.id,
            detail={
                "sender": message.sender,
                "receiver": message.receiver,
                "content_hash": message.content_hash
            },
            commit=False
        )

        if error:
            db.session.rollback()
            return jsonify({"error": error}), 500

        db.session.commit()

    except Exception:
        db.session.rollback()
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

    return jsonify({
        "entries": [
            {
                "seq": entry.seq,
                "event_type": entry.event_type,
                "message_id": entry.message_id,
                "actor_id": entry.actor_id,
                "detail": entry.detail,
                "prev_hash": entry.prev_hash,
                "entry_hash": entry.entry_hash,
                "created_at": entry.created_at.isoformat()
            }
            for entry in entries
        ]
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
