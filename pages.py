"""Frontend pages (Member 3). Registered once in app.py:

    from pages import pages_bp
    app.register_blueprint(pages_bp)
"""
from flask import Blueprint, abort, render_template

pages_bp = Blueprint("pages", __name__)

PAGES = {"index", "send", "inbox", "ledger", "demo"}


@pages_bp.route("/")
def home():
    return render_template("index.html")


@pages_bp.route("/<page>.html")
def page(page):
    if page not in PAGES:
        abort(404)
    return render_template(f"{page}.html")
