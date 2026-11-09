
import pytest

from app import create_app
from app.extensions import db
from app.services import ledger_service


class TestConfig:
    TESTING = True
    SECRET_KEY = "anchor-test-secret"
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


def create_test_entry(monkeypatch):
    # Prevent actual Supabase publishing
    monkeypatch.setattr(
        ledger_service,
        "publish_anchor",
        lambda seq, entry_hash: (True, None)
    )

    entry, error = ledger_service.append_ledger_event(
        event_type="SENT",
        detail={"test": True}
    )

    assert error is None
    return entry


def test_valid_external_anchor(app, monkeypatch):
    with app.app_context():
        entry = create_test_entry(monkeypatch)

        monkeypatch.setattr(
            ledger_service,
            "get_external_anchor",
            lambda: (
                {
                    "latest_seq": entry.seq,
                    "latest_hash": entry.entry_hash
                },
                None
            )
        )

        valid, message = ledger_service.verify_ledger_integrity()

        assert valid is True
        assert "verified successfully" in message


def test_missing_external_anchor(app, monkeypatch):
    with app.app_context():
        create_test_entry(monkeypatch)

        monkeypatch.setattr(
            ledger_service,
            "get_external_anchor",
            lambda: (None, "External anchor not found")
        )

        valid, message = ledger_service.verify_ledger_integrity()

        assert valid is False
        assert message == "External anchor is missing"


def test_external_service_unavailable(app, monkeypatch):
    with app.app_context():
        create_test_entry(monkeypatch)

        monkeypatch.setattr(
            ledger_service,
            "get_external_anchor",
            lambda: (None, "Failed to retrieve external ledger anchor")
        )

        valid, message = ledger_service.verify_ledger_integrity()

        assert valid is False
        assert message == "External anchor service unavailable"


def test_external_anchor_sequence_mismatch(app, monkeypatch):
    with app.app_context():
        entry = create_test_entry(monkeypatch)

        monkeypatch.setattr(
            ledger_service,
            "get_external_anchor",
            lambda: (
                {
                    "latest_seq": entry.seq + 1,
                    "latest_hash": entry.entry_hash
                },
                None
            )
        )

        valid, message = ledger_service.verify_ledger_integrity()

        assert valid is False
        assert message == "External anchor sequence mismatch"


def test_external_anchor_hash_mismatch(app, monkeypatch):
    with app.app_context():
        entry = create_test_entry(monkeypatch)

        monkeypatch.setattr(
            ledger_service,
            "get_external_anchor",
            lambda: (
                {
                    "latest_seq": entry.seq,
                    "latest_hash": "a" * 64
                },
                None
            )
        )

        valid, message = ledger_service.verify_ledger_integrity()

        assert valid is False
        assert message == "External anchor hash mismatch"
