
import base64
from datetime import datetime, timezone, timedelta

import pytest

from cryptography.hazmat.primitives import serialization

from app import create_app
from app.extensions import db
from app.models import (
    User,
    PublicKey,
    Message,
    MessageAttachment,
    LedgerEntry
)

from security.ecdsa import generate_key_pair


class TestConfig:
    TESTING = True
    SECRET_KEY = "expiry-test-secret"
    JWT_SECRET_KEY = "expiry-test-jwt-secret-for-testing-only-2026"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


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


def create_user(client, username, email):
    response = client.post(
        "/api/users",
        json={
            "username": username,
            "email": email,
            "password": "TestPassword123"
        }
    )

    assert response.status_code == 201

    login = client.post(
        "/api/login",
        json={
            "email": email,
            "password": "TestPassword123"
        }
    )

    assert login.status_code == 200

    return login.json["access_token"]


def create_test_message(
    sender_id,
    public_key_id,
    expiry_seconds=None,
    created_at=None
):
    message = Message(
        sender_user_id=sender_id,
        public_key_id=public_key_id,
        sender="sender",
        receiver="receiver",
        timestamp=datetime.now(timezone.utc),
        timestamp_original="2026-11-09T10:00:00Z",
        nonce="expiry-test-nonce",
        message="Confidential test message",
        content_hash="a" * 64,
        signature="test-signature",
        expiry_seconds=expiry_seconds,
        created_at=created_at or datetime.now(timezone.utc)
    )

    db.session.add(message)
    db.session.flush()

    return message


@pytest.fixture
def test_data(client, app):
    with app.app_context():
        sender_token = create_user(
            client, "sender", "sender@test.com"
        )

        receiver_token = create_user(
            client, "receiver", "receiver@test.com"
        )

        sender = User.query.filter_by(
            username="sender"
        ).first()

        private_key, public_key = generate_key_pair()

        public_key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        key = PublicKey(
            user_id=sender.id,
            public_key=base64.b64encode(
                public_key_der
            ).decode("ascii"),
            algorithm="ECDSA-P256"
        )

        db.session.add(key)
        db.session.commit()

        return {
            "sender_id": sender.id,
            "key_id": key.id,
            "sender_token": sender_token,
            "receiver_token": receiver_token
        }


@pytest.mark.parametrize(
    "duration",
    [3600, 86400, 604800, 2592000]
)
def test_supported_expiry_durations(
    app, test_data, duration
):
    with app.app_context():
        message = create_test_message(
            test_data["sender_id"],
            test_data["key_id"],
            expiry_seconds=duration
        )

        assert message.expiry_seconds == duration
        assert message.expires_at is not None
        assert message.is_expired is False


def test_never_expiring_message_remains_accessible(
    app, test_data
):
    with app.app_context():
        old_date = datetime.now(timezone.utc) - timedelta(days=60)

        message = create_test_message(
            test_data["sender_id"],
            test_data["key_id"],
            expiry_seconds=None,
            created_at=old_date
        )

        assert message.expiry_seconds is None
        assert message.expires_at is None
        assert message.is_expired is False


def test_expired_message_is_detected(app, test_data):
    with app.app_context():
        old_date = datetime.now(timezone.utc) - timedelta(hours=2)

        message = create_test_message(
            test_data["sender_id"],
            test_data["key_id"],
            expiry_seconds=3600,
            created_at=old_date
        )

        assert message.is_expired is True


def test_inbox_hides_expired_message_content(
    app, client, test_data
):
    with app.app_context():
        old_date = datetime.now(timezone.utc) - timedelta(hours=2)

        message = create_test_message(
            test_data["sender_id"],
            test_data["key_id"],
            expiry_seconds=3600,
            created_at=old_date
        )

        message_id = message.id

        db.session.add(
            LedgerEntry(
                event_type="SENT",
                message_id=message.id,
                actor_id=test_data["sender_id"],
                detail={"content_hash": message.content_hash},
                prev_hash="b" * 64,
                entry_hash="c" * 64
            )
        )

        db.session.commit()

    response = client.get(
        "/api/messages/inbox",
        headers={
            "Authorization":
                f"Bearer {test_data['receiver_token']}"
        }
    )

    assert response.status_code == 200

    messages = response.json["messages"]
    expired = next(
        item for item in messages
        if item["id"] == message_id
    )

    assert expired["is_expired"] is True
    assert expired["message"] is None
    assert expired["expires_at"] is not None

    assert all(
        item["download_url"] is None
        for item in expired["attachments"]
    )


def test_sent_endpoint_hides_expired_message_content(
    app, client, test_data
):
    with app.app_context():
        old_date = datetime.now(timezone.utc) - timedelta(hours=2)

        message = create_test_message(
            test_data["sender_id"],
            test_data["key_id"],
            expiry_seconds=3600,
            created_at=old_date
        )

        message_id = message.id
        db.session.commit()

    response = client.get(
        "/api/messages/sent",
        headers={
            "Authorization":
                f"Bearer {test_data['sender_token']}"
        }
    )

    assert response.status_code == 200

    expired = next(
        item for item in response.json["messages"]
        if item["id"] == message_id
    )

    assert expired["is_expired"] is True
    assert expired["message"] is None


def test_expired_attachment_download_is_blocked(
    app, client, test_data
):
    with app.app_context():
        old_date = datetime.now(timezone.utc) - timedelta(hours=2)

        message = create_test_message(
            test_data["sender_id"],
            test_data["key_id"],
            expiry_seconds=3600,
            created_at=old_date
        )

        attachment = MessageAttachment(
            message_id=message.id,
            original_filename="evidence.txt",
            stored_filename="test-evidence.txt",
            mime_type="text/plain",
            file_size=100,
            sha256_hash="d" * 64
        )

        db.session.add(attachment)
        db.session.commit()

        message_id = message.id
        attachment_id = attachment.id

    response = client.get(
        f"/api/messages/{message_id}/attachments/{attachment_id}",
        headers={
            "Authorization":
                f"Bearer {test_data['receiver_token']}"
        }
    )

    assert response.status_code == 410
    assert "expired" in response.json["error"].lower()


def test_expiry_preserves_ledger_evidence(
    app, test_data
):
    with app.app_context():
        old_date = datetime.now(timezone.utc) - timedelta(hours=2)

        message = create_test_message(
            test_data["sender_id"],
            test_data["key_id"],
            expiry_seconds=3600,
            created_at=old_date
        )

        message_id = message.id
        original_hash = message.content_hash

        entry = LedgerEntry(
            event_type="SENT",
            message_id=message.id,
            actor_id=test_data["sender_id"],
            detail={
                "content_hash": original_hash,
                "expiry_seconds": 3600
            },
            prev_hash="e" * 64,
            entry_hash="f" * 64
        )

        db.session.add(entry)
        db.session.commit()

        db.session.expire_all()

        stored_message = db.session.get(
            Message, message_id
        )

        stored_entry = LedgerEntry.query.filter_by(
            message_id=message_id
        ).first()

        assert stored_message.is_expired is True
        assert stored_message.message == "Confidential test message"
        assert stored_message.content_hash == original_hash

        assert stored_entry is not None
        assert stored_entry.detail["content_hash"] == original_hash
        assert stored_entry.detail["expiry_seconds"] == 3600
