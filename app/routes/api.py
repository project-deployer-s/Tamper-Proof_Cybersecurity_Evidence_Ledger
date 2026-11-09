
from flask import Blueprint, request, jsonify

from app.services.user_service import register_user
from app.services.key_service import register_public_key
from app.services.message_service import store_message
from app.services.ledger_service import (
    append_ledger_event,
    verify_ledger_integrity
)
from app.services.verification_service import verify_stored_message


api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/users", methods=["POST"])
def create_user():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "JSON data is required"}), 400

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not all([username, email, password]):
        return jsonify({
            "error": "Username, email and password are required"
        }), 400

    if len(password) < 8:
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


@api_bp.route("/users/<int:user_id>/keys", methods=["POST"])
def create_public_key(user_id):

    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "JSON data is required"}), 400

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


@api_bp.route("/messages", methods=["POST"])
def submit_message():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "JSON data is required"}), 400

    required_fields = [
        "sender_user_id",
        "public_key_id",
        "sender",
        "receiver",
        "timestamp",
        "nonce",
        "message",
        "content_hash",
        "signature"
    ]

    if not all(data.get(field) is not None for field in required_fields):
        return jsonify({"error": "Required fields are missing"}), 400

    try:
        user_id = int(data["sender_user_id"])
        key_id = int(data["public_key_id"])
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid user or key ID"}), 400

    msg, error = store_message(
        sender_user_id=user_id,
        public_key_id=key_id,
        sender=data["sender"],
        receiver=data["receiver"],
        timestamp=data["timestamp"],
        nonce=data["nonce"],
        message=data["message"],
        content_hash=data["content_hash"],
        signature=data["signature"]
    )

    if error:
        status = 404 if error == "Sender not found" else 400
        return jsonify({"error": error}), status

    entry, ledger_error = append_ledger_event(
        event_type="SENT",
        message_id=msg.id,
        actor_id=user_id,
        detail={
            "sender": msg.sender,
            "receiver": msg.receiver,
            "content_hash": msg.content_hash
        }
    )

    if ledger_error:
        return jsonify({
            "error": "Message stored, but ledger entry creation failed"
        }), 500

    return jsonify({
        "message": "Message submitted successfully",
        "data": {
            "id": msg.id,
            "sender": msg.sender,
            "receiver": msg.receiver,
            "verification_status": msg.verification_status
        }
    }), 201


@api_bp.route("/messages/<int:message_id>/verify", methods=["POST"])
def verify_message_api(message_id):

    result, error = verify_stored_message(message_id)

    if error:
        status = 404 if error in [
            "Message not found",
            "Sender not found",
            "Public key not found"
        ] else 400

        return jsonify({"error": error}), status

    return jsonify({
        "message": "Verification completed",
        "data": result
    }), 200


@api_bp.route("/ledger/verify", methods=["GET"])
def verify_ledger():

    valid, result = verify_ledger_integrity()

    return jsonify({
        "integrity": "VALID" if valid else "TAMPERED",
        "message": result
    }), 200 if valid else 409
