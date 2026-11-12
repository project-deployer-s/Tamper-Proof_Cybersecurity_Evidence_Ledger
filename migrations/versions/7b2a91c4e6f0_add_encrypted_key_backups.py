"""add client-encrypted signing key backups

Revision ID: 7b2a91c4e6f0
Revises: f45bea6c618d
Create Date: 2026-11-12
"""
from alembic import op
import sqlalchemy as sa

revision = "7b2a91c4e6f0"
down_revision = "f45bea6c618d"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "encrypted_key_backups",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("public_key_id", sa.Integer(), nullable=False),
        sa.Column("ciphertext", sa.Text(), nullable=False),
        sa.Column("salt", sa.String(length=64), nullable=False),
        sa.Column("iv", sa.String(length=64), nullable=False),
        sa.Column("kdf", sa.String(length=40), nullable=False),
        sa.Column("iterations", sa.Integer(), nullable=False),
        sa.Column("cipher", sa.String(length=40), nullable=False),
        sa.Column("format_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["public_key_id"], ["public_keys.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "user_id", "public_key_id",
            name="uq_encrypted_key_backup_user_public_key"
        ),
    )
    with op.batch_alter_table("encrypted_key_backups", schema=None) as batch_op:
        batch_op.create_index("ix_encrypted_key_backups_user_id", ["user_id"], unique=False)
        batch_op.create_index("ix_encrypted_key_backups_public_key_id", ["public_key_id"], unique=False)


def downgrade():
    with op.batch_alter_table("encrypted_key_backups", schema=None) as batch_op:
        batch_op.drop_index("ix_encrypted_key_backups_public_key_id")
        batch_op.drop_index("ix_encrypted_key_backups_user_id")
    op.drop_table("encrypted_key_backups")
