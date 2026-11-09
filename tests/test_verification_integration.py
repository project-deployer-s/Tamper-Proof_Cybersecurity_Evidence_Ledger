from datetime import datetime, timezone, timedelta
import base64
from datetime import datetime, timezone

import pytest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature
)

from app import create_app
from app.extensions import db
from app.models import User, PublicKey, Message, Alert

from app.services.verification_service import verify_stored_message

from security.canonical import create_canonical_payload
from security.hashing import calculate_sha256


# --------------------------------------------------
# TEST CONFIGURATION
# --------------------------------------------------

class TestConfig:
    TESTING = True
    SECRET_KEY = "integration-test-secret"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


# --------------------------------------------------
# PYTEST FIXTURES
# --------------------------------------------------

@pytest.fixture
def app():

    app = create_app(TestConfig)

    with app.app_context():

        db.create_all()

        yield app

        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


# --------------------------------------------------
# HELPER FUNCTION
# --------------------------------------------------

def create_test_message(
    username,
    email,
    nonce,
    message_text
):

    # Generate ECDSA P-256 key pair
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Create user
    user = User(
        username=username,
        email=email
    )

    user.set_password("TestPassword123")

    db.session.add(user)
    db.session.commit()

    # Export public key in DER format
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Encode public key using Base64
    public_key_base64 = base64.b64encode(
        public_key_der
    ).decode("ascii")

    # Register public key
    key_record = PublicKey(
        user_id=user.id,
        public_key=public_key_base64,
        algorithm="ECDSA-P256"
    )

    db.session.add(key_record)
    db.session.commit()

    # Prepare message fields
    sender = username
    receiver = "receiver"
    timestamp = datetime.now(timezone.utc).isoformat()

    # Create canonical payload
    payload = create_canonical_payload(
        sender,
        receiver,
        timestamp,
        nonce,
        message_text
    )

    # Calculate SHA-256 hash
    content_hash = calculate_sha256(payload)

    # Generate ECDSA signature in DER format
    der_signature = private_key.sign(
        payload,
        ec.ECDSA(hashes.SHA256())
    )

    # Convert DER signature to raw 64-byte format
    r, s = decode_dss_signature(der_signature)

    raw_signature = (
        r.to_bytes(32, "big") +
        s.to_bytes(32, "big")
    )

    # Encode signature using Base64
    signature_base64 = base64.b64encode(
        raw_signature
    ).decode("ascii")

    # Create message record
    stored_message = Message(
        sender_user_id=user.id,
        public_key_id=key_record.id,
        sender=sender,
        receiver=receiver,
        timestamp=datetime.fromisoformat(timestamp),
        timestamp_original=timestamp,
        nonce=nonce,
        message=message_text,
        content_hash=content_hash,
        signature=signature_base64
    )

    db.session.add(stored_message)
    db.session.commit()

    return stored_message, raw_signature


# --------------------------------------------------
# TEST 1: GENUINE MESSAGE VERIFICATION
# --------------------------------------------------

def test_genuine_message_verification(app):

    with app.app_context():

        stored_message, raw_signature = create_test_message(
            "testuser",
            "test@example.com",
            "genuine-nonce-001",
            "This is a genuine signed message"
        )

        result, error = verify_stored_message(
            stored_message.id
        )

        assert error is None
        assert result["verdict"] == "GENUINE"
        assert result["ledger_seq"] is not None
        assert result["alert_id"] is None


# --------------------------------------------------
# TEST 2: TAMPERING DETECTION
# --------------------------------------------------

def test_tampered_message_detection(app):

    with app.app_context():

        stored_message, raw_signature = create_test_message(
            "tamperuser",
            "tamper@example.com",
            "tamper-nonce-001",
            "Original secure message"
        )

        # Modify message after signing
        stored_message.message = "Modified malicious message"

        db.session.commit()

        # Verify modified message
        result, error = verify_stored_message(
            stored_message.id
        )

        assert error is None
        assert result["verdict"] == "TAMPERED"
        assert result["alert_id"] is not None

        # Check generated alert
        alert = db.session.get(
            Alert,
            result["alert_id"]
        )

        assert alert is not None
        assert alert.severity == "HIGH"
        assert alert.alert_type == "TAMPERED"


# --------------------------------------------------
# TEST 3: INVALID SIGNATURE DETECTION
# --------------------------------------------------

def test_invalid_signature_detection(app):

    with app.app_context():

        stored_message, raw_signature = create_test_message(
            "invalidsiguser",
            "invalidsig@example.com",
            "invalid-signature-nonce-001",
            "Original signed message"
        )

        # Modify signature without changing message or hash
        modified_signature = bytearray(raw_signature)

        modified_signature[0] ^= 0x01

        stored_message.signature = base64.b64encode(
            modified_signature
        ).decode("ascii")

        db.session.commit()

        # Verify message
        result, error = verify_stored_message(
            stored_message.id
        )

        assert error is None
        assert result["verdict"] == "INVALID_SIGNATURE"
        assert result["alert_id"] is not None

        # Check generated alert
        alert = db.session.get(
            Alert,
            result["alert_id"]
        )

        assert alert is not None
        assert alert.severity == "HIGH"
        assert alert.alert_type == "INVALID_SIGNATURE"


def test_replay_attack_detection(app):

    with app.app_context():

        # 1. Create the original signed message
        original, raw_signature = create_test_message(
            "replayuser",
            "replay@example.com",
            "replay-nonce-001",
            "Captured signed message"
        )

        # 2. Verify the original message first
        first_result, first_error = verify_stored_message(
            original.id
        )

        assert first_error is None
        assert first_result["verdict"] == "GENUINE"

        # 3. Create a second message using the same nonce
        replay = Message(
            sender_user_id=original.sender_user_id,
            public_key_id=original.public_key_id,
            sender=original.sender,
            receiver=original.receiver,
            timestamp=original.timestamp,
            timestamp_original=original.timestamp_original,
            nonce=original.nonce,
            message=original.message,
            content_hash=original.content_hash,
            signature=original.signature
        )

        db.session.add(replay)
        db.session.commit()

        # 4. Verify the replayed message
        result, error = verify_stored_message(replay.id)

        # 5. Check replay detection
        assert error is None
        assert result["verdict"] == "REPLAY"
        assert result["alert_id"] is not None

        # 6. Confirm HIGH severity alert
        alert = db.session.get(Alert, result["alert_id"])

        assert alert is not None
        assert alert.severity == "HIGH"
        assert alert.alert_type == "REPLAY"

def test_expired_message_detection(app):
    with app.app_context():
        stored_message, _ = create_test_message(
            "expireduser",
            "expired@example.com",
            "expired-nonce-001",
            "Old message"
        )

        old_timestamp = datetime.now(timezone.utc) - timedelta(minutes=10)

        stored_message.timestamp = old_timestamp
        stored_message.timestamp_original = old_timestamp.isoformat()
        db.session.commit()

        result, error = verify_stored_message(stored_message.id)

        assert error is None
        assert result["verdict"] == "EXPIRED"
        assert result["alert_id"] is not None

def test_unknown_sender_detection(app):
    with app.app_context():
        stored_message, _ = create_test_message(
            "knownuser",
            "known@example.com",
            "unknown-nonce-001",
            "Test message"
        )

        stored_message.sender = "unknownuser"
        db.session.commit()

        result, error = verify_stored_message(stored_message.id)

        assert error is None
        assert result["verdict"] == "UNKNOWN_SENDER"
        assert result["alert_id"] is not None

def test_revoked_key_detection(app):
    with app.app_context():
        stored_message, _ = create_test_message(
            "revokeduser",
            "revoked@example.com",
            "revoked-nonce-001",
            "Test message"
        )

        key = db.session.get(PublicKey, stored_message.public_key_id)
        key.is_revoked = True
        db.session.commit()

        result, error = verify_stored_message(stored_message.id)

        assert error is None
        assert result["verdict"] == "REVOKED_KEY"
        assert result["alert_id"] is not None