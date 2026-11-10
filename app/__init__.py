from pathlib import Path
import os

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

from app.routes.api import api_bp
from flask import Flask, jsonify, render_template

from app.config import Config
from app.extensions import db, migrate, limiter, jwt
from pages import pages_bp


def create_app(config_class=Config):

    load_dotenv()

    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static"
    )

    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)
    jwt.init_app(app)

    # Register database models
    from app import models

    @app.cli.command("retry-anchors")
    def retry_anchors_command():
        """Retry pending external ledger anchors."""

        from app.services.anchor_service import retry_pending_anchors

        with app.app_context():
            result = retry_pending_anchors()

        print("Anchor retry results:", result)

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