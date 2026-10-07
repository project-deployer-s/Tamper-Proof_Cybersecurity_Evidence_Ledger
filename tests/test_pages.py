from pathlib import Path

import pytest
from flask import Flask

from pages import pages_bp

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def client():
    app = Flask("pages_test", root_path=str(ROOT))
    app.register_blueprint(pages_bp)
    return app.test_client()


@pytest.mark.parametrize("path", ["/", "/index.html", "/send.html", "/inbox.html",
                                  "/ledger.html", "/demo.html",
                                  "/static/css/styles.css", "/static/js/app.js",
                                  "/static/js/mock-api.js"])
def test_page_loads(client, path):
    assert client.get(path).status_code == 200


def test_unknown_page_is_404(client):
    assert client.get("/nope.html").status_code == 404
