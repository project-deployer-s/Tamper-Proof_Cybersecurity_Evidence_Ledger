
import base64
import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature
)

from app import create_app
from app.extensions import db
from app.models import Message

from security.canonical import create_canonical_payload
from security.ecdsa import generate_key_pair, sign_data
from security.hashing import calculate_sha256


class TestConfig:
    TESTING = True
    SECRET_KEY = "authentication-test-secret"
    JWT_SECRET_KEY = "authentication-test-jwt-secret-key-2026"
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


def register_user(client, username, email):
    return client.post(
        "/api/users",
        json={
            "username": username,
            "email": email,
            "password": "TestPassword123"
        }
    )


def login_user(client, email):
    return client.post(
        "/api/login",
        json={
            "email": email,
            "password": "TestPassword123"
        }
    )


def create_signed_test_message(
    private_key,
    sender,
    receiver,
    message
):
    timestamp = "2026-11-09T10:00:00Z"
    nonce = "test-nonce"

    canonical_payload = create_canonical_payload(
        sender=sender,
        receiver=receiver,
        timestamp=timestamp,
        nonce=nonce,
        message=message
    )

    content_hash = calculate_sha256(canonical_payload)

    der_signature = sign_data(
        private_key,
        canonical_payload
    )

    r, s = decode_dss_signature(der_signature)

    raw_signature = (
        r.to_bytes(32, byteorder="big") +
        s.to_bytes(32, byteorder="big")
    )

    return {
        "sender": sender,
        "receiver": receiver,
        "timestamp": timestamp,
        "nonce": nonce,
        "message": message,
        "content_hash": content_hash,
        "signature": base64.b64encode(
            raw_signature
        ).decode("ascii")
    }


def register_test_key(client, user_id, token):
    private_key, public_key = generate_key_pair()

    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    public_key_base64 = base64.b64encode(
        public_key_der
    ).decode("ascii")

    response = client.post(
        f"/api/users/{user_id}/keys",
        headers={"Authorization": f"Bearer {token}"},
        json={"public_key": public_key_base64}
    )

    assert response.status_code == 201

    return private_key, response.json["key"]["id"]


def test_successful_login(client):
    register_user(client, "user1", "user1@test.com")

    response = login_user(client, "user1@test.com")

    assert response.status_code == 200
    assert "access_token" in response.json


def test_login_with_wrong_password(client):
    register_user(client, "user1", "user1@test.com")

    response = client.post(
        "/api/login",
        json={
            "email": "user1@test.com",
            "password": "WrongPassword"
        }
    )

    assert response.status_code == 401


def test_login_with_unknown_email(client):
    response = login_user(client, "unknown@test.com")

    assert response.status_code == 401


def test_protected_endpoint_without_token(client):
    response = client.post(
        "/api/users/1/keys",
        json={"public_key": "test-key"}
    )

    assert response.status_code == 401


def test_protected_endpoint_with_valid_token(client):
    register_user(client, "user1", "user1@test.com")

    login_response = login_user(client, "user1@test.com")
    token = login_response.json["access_token"]

    response = client.post(
        "/api/users/1/keys",
        headers={"Authorization": f"Bearer {token}"},
        json={}
    )

    assert response.status_code == 400


def test_user_cannot_register_key_for_another_user(client):
    register_user(client, "user1", "user1@test.com")
    register_user(client, "user2", "user2@test.com")

    login_response = login_user(client, "user1@test.com")
    token = login_response.json["access_token"]

    response = client.post(
        "/api/users/2/keys",
        headers={"Authorization": f"Bearer {token}"},
        json={"public_key": "test-public-key"}
    )

    assert response.status_code == 403


def test_user_cannot_send_message_using_another_users_key(client):
    register_user(client, "user1", "user1@test.com")
    register_user(client, "user2", "user2@test.com")

    # Register a key belonging to user2.
    user2_login = login_user(client, "user2@test.com")
    user2_token = user2_login.json["access_token"]

    _, key_id = register_test_key(
        client, 2, user2_token
    )

    # User1 attempts to use user2's key.
    user1_login = login_user(client, "user1@test.com")
    user1_token = user1_login.json["access_token"]

    response = client.post(
        "/api/messages",
        headers={
            "Authorization": f"Bearer {user1_token}"
        },
        json={
            "sender": "user1",
            "receiver": "user2",
            "public_key_id": key_id,
            "timestamp": "2026-11-09T10:00:00Z",
            "nonce": "test-nonce",
            "message": "Test message",
            "content_hash": "test-hash",
            "signature": "test-signature"
        }
    )

    assert response.status_code == 400
    assert response.json["error"] == "Invalid or revoked signing key"


def test_message_is_rolled_back_when_ledger_creation_fails(
    client, monkeypatch
):
    register_user(client, "user1", "user1@test.com")
    register_user(client, "user2", "user2@test.com")

    login_response = login_user(client, "user1@test.com")
    token = login_response.json["access_token"]

    headers = {
        "Authorization": f"Bearer {token}"
    }

    # Register a valid ECDSA P-256 key.
    private_key, key_id = register_test_key(
        client, 1, token
    )

    # Generate a correctly signed message.
    signed_data = create_signed_test_message(
        private_key,
        "user1",
        "user2",
        "Test message"
    )

    payload = {
        "public_key_id": key_id,
        **signed_data
    }

    # Simulate ledger creation failure.
    def fail_ledger(**kwargs):
        return None, "Simulated ledger failure"

    monkeypatch.setattr(
        "app.routes.api.append_ledger_event",
        fail_ledger
    )

    response = client.post(
        "/api/messages",
        headers=headers,
        json=payload
    )

    assert response.status_code == 500

    # Confirm the database transaction was rolled back.
    with client.application.app_context():
        assert Message.query.count() == 0
