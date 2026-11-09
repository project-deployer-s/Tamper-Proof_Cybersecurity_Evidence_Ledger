from app.extensions import db
from app.models import Alert, LedgerEntry


def create_alert(
    ledger_seq,
    alert_type,
    severity="HIGH",
    commit=True
):

    # Check whether ledger entry exists
    entry = db.session.get(LedgerEntry, ledger_seq)

    if not entry:
        return None, "Ledger entry not found"

    # Create alert
    alert = Alert(
        ledger_seq=ledger_seq,
        alert_type=alert_type,
        severity=severity
    )

    db.session.add(alert)
    db.session.flush()

    if commit:
        db.session.commit()

    return alert, None


def acknowledge_alert(alert_id):

    alert = db.session.get(Alert, alert_id)

    if not alert:
        return None, "Alert not found"

    alert.acknowledge()
    db.session.commit()

    return alert, None
