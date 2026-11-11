from datetime import timedelta
import os


def normalize_database_url(url):
    """Normalize PostgreSQL URLs for Psycopg 3."""

    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg://", 1)

    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)

    return url


ENVIRONMENT = os.getenv(
    "APP_ENV",
    os.getenv("FLASK_ENV", "development")
).lower()

SECRET = os.getenv("SECRET_KEY")

DATABASE_URL = normalize_database_url(
    os.getenv("DATABASE_URL", "sqlite:///evidence_ledger.db")
)

REDIS_URL = os.getenv("REDIS_URL", "memory://")


if ENVIRONMENT == "production":

    if not SECRET or len(SECRET) < 64:
        raise RuntimeError(
            "Production requires a SECRET_KEY of at least 64 characters."
        )

    if not DATABASE_URL.startswith("postgresql+psycopg://"):
        raise RuntimeError(
            "Production requires a PostgreSQL database."
        )

    if REDIS_URL == "memory://":
        raise RuntimeError(
            "Production requires REDIS_URL for shared rate limiting."
        )


class Config:

    ENVIRONMENT = ENVIRONMENT

    # Application security
    SECRET_KEY = SECRET or "local-development-key-change-before-deployment"
    JWT_SECRET_KEY = SECRET or "local-development-key-change-before-deployment"

    # JWT authentication
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
    JWT_ALGORITHM = "HS256"

    # Database
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True
    }

    # Redis rate limiting
    RATELIMIT_STORAGE_URI = REDIS_URL

    # Session security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = ENVIRONMENT == "production"
