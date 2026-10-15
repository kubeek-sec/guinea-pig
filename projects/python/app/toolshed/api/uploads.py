"""Condition photos attached to a rental."""
import os
import uuid

from flask import Blueprint, current_app, g, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

from ..core import auth

bp = Blueprint("uploads", __name__)

ALLOWED = {".jpg", ".jpeg", ".png", ".webp"}


@bp.post("/api/photos")
@auth.login_required
def upload_photo():
    item = request.files.get("photo")
    if item is None or not item.filename:
        return jsonify(error="no photo"), 400
    ext = os.path.splitext(item.filename)[1].lower()
    if ext not in ALLOWED:
        return jsonify(error=f"{ext or 'file'} not accepted"), 400
    name = f"{uuid.uuid4().hex}{ext}"
    item.save(os.path.join(current_app.config["UPLOAD_DIR"], name))
    return jsonify(name=name, owner=g.member["email"]), 201


@bp.get("/api/photos/<name>")
def fetch_photo(name: str):
    safe = secure_filename(name)
    directory = current_app.config["UPLOAD_DIR"]
    if not os.path.isfile(os.path.join(directory, safe)):
        return jsonify(error="no such photo"), 404
    response = send_from_directory(directory, safe)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
