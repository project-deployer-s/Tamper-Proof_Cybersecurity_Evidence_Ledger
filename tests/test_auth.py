
from app.models import Message
import pytest

from app import create_app
from app.extensions import db


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

    login_response = login_user(client, "user1@test.com")
    token = login_response.json["access_token"]

    response = client.post(
        "/api/messages",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "sender_user_id": 1,
            "public_key_id": 999,
            "sender": "user1",
            "receiver": "user2",
            "timestamp": "2026-11-09T10:00:00Z",
            "nonce": "test-nonce",
            "message": "Test message",
            "content_hash": "test-hash",
            "signature": "test-signature"
        }
    )

    assert response.status_code == 400
    assert response.json["error"] == "Invalid public key"


def test_message_is_rolled_back_when_ledger_creation_fails(
    client, monkeypatch
):
    register_user(client, "user1", "user1@test.com")
    register_user(client, "user2", "user2@test.com")

    login_response = login_user(client, "user1@test.com")
    token = login_response.json["access_token"]

    headers = {"Authorization": f"Bearer {token}"}

    key_response = client.post(
        "/api/users/1/keys",
        headers=headers,
        json={"public_key": "test-public-key"}
    )

    assert key_response.status_code == 201

    key_id = key_response.json["key"]["id"]

    def fail_ledger(**kwargs):
        return None, "Simulated ledger failure"

    monkeypatch.setattr(
        "app.routes.api.append_ledger_event",
        fail_ledger
    )

    response = client.post(
        "/api/messages",
        headers=headers,
        json={
            "sender_user_id": 1,
            "public_key_id": key_id,
            "sender": "user1",
            "receiver": "user2",
            "timestamp": "2026-11-09T10:00:00Z",
            "nonce": "test-nonce",
            "message": "Test message",
            "content_hash": "test-hash",
            "signature": "test-signature"
        }
    )

    assert response.status_code == 500

    with client.application.app_context():
        assert Message.query.count() == 0
