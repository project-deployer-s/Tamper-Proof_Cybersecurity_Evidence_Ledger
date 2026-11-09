
import os


def normalize_database_url(url):
    """Normalize PostgreSQL URLs for the Psycopg 3 driver."""

    if url.startswith("postgres://"):
        return url.replace(
            "postgres://",
            "postgresql+psycopg://",
            1
        )

    if url.startswith("postgresql://"):
        return url.replace(
            "postgresql://",
            "postgresql+psycopg://",
            1
        )

    return url


ENVIRONMENT = os.getenv("FLASK_ENV", "development")
SECRET = os.getenv("SECRET_KEY")

if ENVIRONMENT == "production":
    if not SECRET or len(SECRET) < 64:
        raise RuntimeError(
            "Production requires a SECRET_KEY of at least 64 characters."
        )

    if SECRET == "replace-with-a-secure-random-secret":
        raise RuntimeError("Replace the default SECRET_KEY before deployment.")


class Config:
    SECRET_KEY = SECRET or "local-development-key-change-before-deployment"

    SQLALCHEMY_DATABASE_URI = normalize_database_url(
        os.getenv(
            "DATABASE_URL",
            "sqlite:///evidence_ledger.db"
        )
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True
    }

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = ENVIRONMENT == "production"
