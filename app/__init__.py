from pathlib import Path
import os

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

from app.routes.api import api_bp
from flask import Flask, jsonify, render_template

from app.config import Config
from app.extensions import db, migrate, limiter
from pages import pages_bp


def create_app(config_class=Config):

    load_dotenv()

    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static"
    )

    app.config.from_object(config_class)

    app.config["RATELIMIT_STORAGE_URI"] = os.getenv(
    "REDIS_URL",
    "memory://"
    )

    db.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)

    # Register database models
    from app import models

    # Register frontend routes
    app.register_blueprint(pages_bp)
    app.register_blueprint(api_bp)

    @app.route("/health")
    def health():
        return jsonify({
            "status": "healthy"
        }), 200

    @app.route("/crypto-test")
    def crypto_test():
        return render_template("crypto_test.html")

    return app