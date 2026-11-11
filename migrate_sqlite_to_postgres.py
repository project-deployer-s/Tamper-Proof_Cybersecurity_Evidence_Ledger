
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import (
    create_engine,
    MetaData,
    DateTime,
    JSON,
    Boolean,
    select,
    text,
    inspect,
)

TABLES = [
    "users",
    "public_keys",
    "messages",
    "ledger_entries",
    "alerts",
    "anchor_outbox",
    "message_attachments",
]

PRIMARY_KEYS = {
    "users": "id",
    "public_keys": "id",
    "messages": "id",
    "ledger_entries": "seq",
    "alerts": "id",
    "anchor_outbox": "id",
    "message_attachments": "id",
}

EXPECTED_COUNTS = {
    "users": 2,
    "public_keys": 3,
    "messages": 9,
    "ledger_entries": 64,
    "alerts": 27,
    "anchor_outbox": 64,
    "message_attachments": 4,
}

DB_PATH = Path("instance/evidence_ledger.db")


def convert_value(value, column_type):
    if value is None:
        return None

    if isinstance(column_type, DateTime):
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    if isinstance(column_type, JSON):
        return json.loads(value) if isinstance(value, str) else value

    if isinstance(column_type, Boolean):
        return bool(value)

    return value


def main():
    load_dotenv(Path.cwd() / ".env", override=True)

    database_url = os.getenv("DATABASE_URL", "")

    if database_url.startswith("postgres://"):
        database_url = database_url.replace(
            "postgres://", "postgresql+psycopg://", 1
        )
    elif database_url.startswith("postgresql://"):
        database_url = database_url.replace(
            "postgresql://", "postgresql+psycopg://", 1
        )

    if not database_url.startswith("postgresql+psycopg://"):
        raise RuntimeError("PostgreSQL DATABASE_URL is not configured.")

    if not DB_PATH.exists():
        raise RuntimeError("SQLite source database not found.")

    source = sqlite3.connect(
        f"file:{DB_PATH.resolve()}?mode=ro",
        uri=True,
    )
    source.row_factory = sqlite3.Row

    engine = create_engine(database_url, pool_pre_ping=True)

    try:
        source.execute("PRAGMA query_only = ON")

        print("Checking SQLite source...")

        source_rows = {}

        for table_name in TABLES:
            rows = source.execute(
                f'SELECT * FROM "{table_name}" '
                f'ORDER BY "{PRIMARY_KEYS[table_name]}"'
            ).fetchall()

            if len(rows) != EXPECTED_COUNTS[table_name]:
                raise RuntimeError(
                    f"Unexpected source count in {table_name}: "
                    f"{len(rows)}"
                )

            source_rows[table_name] = [
                dict(row) for row in rows
            ]

            print(f"{table_name}: {len(rows)} source records")

        print("\nChecking PostgreSQL target...")

        metadata = MetaData()

        with engine.begin() as conn:
            inspector = inspect(conn)
            existing_tables = inspector.get_table_names()

            for table_name in TABLES:
                if table_name not in existing_tables:
                    raise RuntimeError(
                        f"Target table missing: {table_name}"
                    )

                count = conn.execute(
                    text(f'SELECT COUNT(*) FROM "{table_name}"')
                ).scalar_one()

                if count != 0:
                    raise RuntimeError(
                        f"Target table {table_name} is not empty."
                    )

            metadata.reflect(bind=conn, only=TABLES)

            print("All target tables are empty.")
            print("\nStarting transactional migration...")

            converted_rows = {}

            for table_name in TABLES:
                table = metadata.tables[table_name]
                rows = []

                for source_row in source_rows[table_name]:
                    converted = {}

                    for column in table.columns:
                        converted[column.name] = convert_value(
                            source_row[column.name],
                            column.type,
                        )

                    rows.append(converted)

                converted_rows[table_name] = rows

                conn.execute(table.insert(), rows)

                print(
                    f"Inserted {len(rows)} records into {table_name}"
                )

            print("\nResetting PostgreSQL sequences...")

            for table_name, pk in PRIMARY_KEYS.items():
                conn.execute(
                    text(
                        f"""
                        SELECT setval(
                            pg_get_serial_sequence(
                                '{table_name}', '{pk}'
                            ),
                            (SELECT MAX("{pk}") FROM "{table_name}"),
                            true
                        )
                        """
                    )
                )

            print("\nVerifying every migrated record...")

            for table_name in TABLES:
                table = metadata.tables[table_name]
                pk = PRIMARY_KEYS[table_name]

                target_rows = conn.execute(
                    select(table).order_by(table.c[pk])
                ).mappings().all()

                expected_rows = converted_rows[table_name]

                if len(target_rows) != len(expected_rows):
                    raise RuntimeError(
                        f"Record count mismatch: {table_name}"
                    )

                for index, (expected, actual) in enumerate(
                    zip(expected_rows, target_rows)
                ):
                    for column in table.columns:
                        name = column.name

                        if expected[name] != actual[name]:
                            raise RuntimeError(
                                f"Data mismatch: {table_name}, "
                                f"record {index}, column {name}"
                            )

                print(
                    f"{table_name}: "
                    f"{len(target_rows)} records verified"
                )

            total = sum(EXPECTED_COUNTS.values())

            print(f"\nAll {total} records verified.")
            print("Transaction ready to commit.")

        print("\nMIGRATION SUCCESSFUL.")
        print("PostgreSQL transaction committed.")
        print("SQLite source was not modified.")

    finally:
        source.close()
        engine.dispose()


if __name__ == "__main__":
    main()
