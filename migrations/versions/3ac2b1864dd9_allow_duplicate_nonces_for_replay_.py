
"""Allow duplicate nonces for replay detection

Revision ID: 3ac2b1864dd9
Revises: 2586250b0837
"""

from alembic import op


revision = '3ac2b1864dd9'
down_revision = '2586250b0837'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table(
        'messages',
        naming_convention={
            "uq": "uq_%(table_name)s_%(column_0_name)s"
        }
    ) as batch_op:

        # Remove the old unique constraint
        batch_op.drop_constraint(
            "uq_messages_nonce",
            type_="unique"
        )

        # Add a normal non-unique index
        batch_op.create_index(
            "ix_messages_nonce",
            ["nonce"],
            unique=False
        )


def downgrade():
    with op.batch_alter_table(
        'messages',
        naming_convention={
            "uq": "uq_%(table_name)s_%(column_0_name)s"
        }
    ) as batch_op:

        batch_op.drop_index("ix_messages_nonce")

        # Restore the unique constraint
        batch_op.create_unique_constraint(
            "uq_messages_nonce",
            ["nonce"]
        )
