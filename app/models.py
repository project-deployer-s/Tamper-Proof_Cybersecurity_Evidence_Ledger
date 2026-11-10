from datetime import datetime, timezone

from werkzeug.security import generate_password_hash, check_password_hash

from app.extensions import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False,
        index=True
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False,
        index=True
    )

    password_hash = db.Column(
        db.String(256),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        nullable=False,
        default="user"
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    public_keys = db.relationship(
        "PublicKey",
        back_populates="owner",
        cascade="save-update, merge"
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"

class PublicKey(db.Model):
    __tablename__ = "public_keys"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    public_key = db.Column(
        db.Text,
        nullable=False
    )

    algorithm = db.Column(
        db.String(30),
        nullable=False,
        default="ECDSA-P256"
    )

    is_revoked = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    revoked_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True
    )

    owner = db.relationship(
        "User",
        back_populates="public_keys"
    )

    def revoke(self):
        self.is_revoked = True
        self.revoked_at = datetime.now(timezone.utc)

    def __repr__(self):
        return f"<PublicKey {self.id}>"

class Message(db.Model):
    __tablename__ = "messages"

    id = db.Column(db.Integer, primary_key=True)

    sender_user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    public_key_id = db.Column(
        db.Integer,
        db.ForeignKey("public_keys.id"),
        nullable=False
    )

    sender = db.Column(
        db.String(120),
        nullable=False
    )

    receiver = db.Column(
        db.String(120),
        nullable=False
    )

    timestamp = db.Column(
        db.DateTime(timezone=True),
        nullable=False
    )

    timestamp_original = db.Column(
    db.String(50),
    nullable=False
)

    nonce = db.Column(
    db.String(128),
    nullable=False,
    index=True
)

    message = db.Column(
        db.Text,
        nullable=False
    )

    content_hash = db.Column(
        db.String(64),
        nullable=False
    )

    signature = db.Column(
        db.Text,
        nullable=False
    )

    verification_status = db.Column(
        db.String(30),
        nullable=False,
        default="PENDING"
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    sender_user = db.relationship("User")
    signing_key = db.relationship("PublicKey")

    def __repr__(self):
        return f"<Message {self.id}: {self.verification_status}>"

class LedgerEntry(db.Model):
    __tablename__ = "ledger_entries"

    seq = db.Column(db.Integer, primary_key=True)

    event_type = db.Column(db.String(30), nullable=False)

    message_id = db.Column(
        db.Integer,
        db.ForeignKey("messages.id"),
        nullable=True,
        index=True
    )

    actor_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True
    )

    detail = db.Column(db.JSON, nullable=False, default=dict)

    prev_hash = db.Column(db.String(64), nullable=False)

    entry_hash = db.Column(
        db.String(64),
        nullable=False,
        unique=True
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    message_record = db.relationship("Message")
    actor = db.relationship("User")

    def __repr__(self):
        return f"<LedgerEntry {self.seq}: {self.event_type}>"

class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)

    ledger_seq = db.Column(
        db.Integer,
        db.ForeignKey("ledger_entries.seq"),
        nullable=False,
        index=True
    )

    alert_type = db.Column(db.String(50), nullable=False)

    severity = db.Column(db.String(20), nullable=False, default="HIGH")

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    acknowledged = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    ledger_entry = db.relationship("LedgerEntry")

    def acknowledge(self):
        self.acknowledged = True

    def __repr__(self):
        return f"<Alert {self.id}: {self.alert_type}>"

class AnchorOutbox(db.Model):
    __tablename__ = "anchor_outbox"

    id = db.Column(db.Integer, primary_key=True)

    ledger_seq = db.Column(
        db.Integer,
        db.ForeignKey("ledger_entries.seq"),
        nullable=False,
        unique=True,
        index=True
    )

    entry_hash = db.Column(
        db.String(64),
        nullable=False
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="PENDING"
    )

    retry_count = db.Column(
        db.Integer,
        nullable=False,
        default=0
    )

    last_error = db.Column(
        db.Text,
        nullable=True
    )

    next_retry_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc)
    )

    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    ledger_entry = db.relationship("LedgerEntry")

    def __repr__(self):
        return f"<AnchorOutbox {self.ledger_seq}: {self.status}>"