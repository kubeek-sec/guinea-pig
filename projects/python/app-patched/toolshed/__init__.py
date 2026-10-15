"""Toolshed — a small tool-rental service for a neighbourhood workshop."""
import os

from flask import Flask, jsonify, send_from_directory

from .core import db
from .api import catalog, members, rentals, uploads

__version__ = "1.4.2"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates")
    app.config.update(
        DATABASE=os.environ.get("TOOLSHED_DB", os.path.join(BASE_DIR, "..", "var", "toolshed.db")),
        UPLOAD_DIR=os.environ.get("TOOLSHED_UPLOADS", os.path.join(BASE_DIR, "..", "var", "uploads")),
        TOKEN_TTL=int(os.environ.get("TOOLSHED_TOKEN_TTL", 3600)),
    )
    if config:
        app.config.update(config)

    db.init_app(app)

    app.register_blueprint(catalog.bp)
    app.register_blueprint(members.bp)
    app.register_blueprint(rentals.bp)
    app.register_blueprint(uploads.bp)

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok", version=__version__)

    @app.get("/openapi.yml")
    def openapi():
        return send_from_directory(os.path.join(BASE_DIR, ".."), "openapi.yml",
                                   mimetype="application/yaml")

    return app
