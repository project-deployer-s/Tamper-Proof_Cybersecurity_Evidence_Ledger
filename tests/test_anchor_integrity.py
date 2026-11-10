
import pytest

from app import create_app
from app.extensions import db
from app.models import LedgerEntry
from app.services import ledger_service


# --------------------------------------------------
# TEST CONFIGURATION
# --------------------------------------------------

class TestConfig:
    TESTING = True
    SECRET_KEY = "anchor-test-secret"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


# --------------------------------------------------
# FIXTURES
# --------------------------------------------------

@pytest.fixture
def app():
    app = create_app(TestConfig)

    with app.app_context():
        db.create_all()

        yield app

        db.session.remove()
        db.drop_all()


# --------------------------------------------------
# HELPER FUNCTION
# --------------------------------------------------

def create_test_entry(monkeypatch):

    # Prevent actual Supabase publishing
    monkeypatch.setattr(
        ledger_service,
        "publish_and_update_outbox",
        lambda seq, entry_hash: (True, None)
    )

    entry, error = ledger_service.append_ledger_event(
        event_type="SENT",
        detail={"test": True}
    )

    assert error is None
    assert entry is not None

    # Mock external historical anchors using local ledger data
    def mock_anchor_history():
        entries = LedgerEntry.query.order_by(
            LedgerEntry.seq.asc()
        ).all()

        history = [
            {
                "seq": item.seq,
                "entry_hash": item.entry_hash
            }
            for item in entries
        ]

        return history, None

    monkeypatch.setattr(
        ledger_service,
        "get_anchor_history",
        mock_anchor_history
    )

    return entry


# --------------------------------------------------
# TEST 1: VALID EXTERNAL ANCHOR
# --------------------------------------------------

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


# --------------------------------------------------
# TEST 2: MISSING EXTERNAL ANCHOR
# --------------------------------------------------

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


# --------------------------------------------------
# TEST 3: EXTERNAL SERVICE UNAVAILABLE
# --------------------------------------------------

def test_external_service_unavailable(app, monkeypatch):

    with app.app_context():

        create_test_entry(monkeypatch)

        monkeypatch.setattr(
            ledger_service,
            "get_external_anchor",
            lambda: (
                None,
                "Failed to retrieve external ledger anchor"
            )
        )

        valid, message = ledger_service.verify_ledger_integrity()

        assert valid is False
        assert message == "External anchor service unavailable"


# --------------------------------------------------
# TEST 4: SEQUENCE MISMATCH
# --------------------------------------------------

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


# --------------------------------------------------
# TEST 5: HASH MISMATCH
# --------------------------------------------------

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
