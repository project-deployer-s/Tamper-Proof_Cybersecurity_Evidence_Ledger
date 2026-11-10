
from app.extensions import db
from app.models import Alert, LedgerEntry


def create_alert(
    ledger_seq,
    alert_type,
    severity="HIGH",
    commit=True
):
    """
    Create a security alert linked to a ledger entry.

    When commit=False, the caller controls the transaction.
    """

    # 1. Check whether ledger entry exists
    entry = db.session.get(LedgerEntry, ledger_seq)

    if not entry:
        return None, "Ledger entry not found"

    try:
        # 2. Create alert
        alert = Alert(
            ledger_seq=ledger_seq,
            alert_type=alert_type,
            severity=severity
        )

        db.session.add(alert)
        db.session.flush()

        # 3. Commit only when requested
        if commit:
            db.session.commit()

        return alert, None

    except Exception as exc:
        db.session.rollback()

        print("ALERT CREATION ERROR:", repr(exc))

        return None, "Failed to create security alert"


def acknowledge_alert(alert_id):
    """Acknowledge an existing security alert."""

    # 1. Retrieve alert
    alert = db.session.get(Alert, alert_id)

    if not alert:
        return None, "Alert not found"

    try:
        # 2. Update acknowledgement status
        alert.acknowledge()

        # 3. Commit changes
        db.session.commit()

        return alert, None

    except Exception as exc:
        db.session.rollback()

        print("ALERT ACKNOWLEDGEMENT ERROR:", repr(exc))

        return None, "Failed to acknowledge alert"
