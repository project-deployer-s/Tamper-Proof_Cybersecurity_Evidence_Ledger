
import sqlalchemy as sa
from alembic import op


revision = '3ac2b1864dd9'
down_revision = '2586250b0837'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()

    if bind.dialect.name == "postgresql":
        # Find the actual PostgreSQL constraint name
        constraints = sa.inspect(bind).get_unique_constraints("messages")

        nonce_constraint = next(
            (
                constraint["name"]
                for constraint in constraints
                if constraint["column_names"] == ["nonce"]
            ),
            None
        )

        if nonce_constraint is None:
            raise RuntimeError("Unique nonce constraint not found.")

        op.drop_constraint(
            nonce_constraint,
            "messages",
            type_="unique"
        )

        op.create_index(
            "ix_messages_nonce",
            "messages",
            ["nonce"],
            unique=False
        )

    else:
        # Preserve the existing SQLite migration behavior
        with op.batch_alter_table(
            "messages",
            naming_convention={
                "uq": "uq_%(table_name)s_%(column_0_name)s"
            }
        ) as batch_op:

            batch_op.drop_constraint(
                "uq_messages_nonce",
                type_="unique"
            )

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
