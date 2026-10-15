"""Member accounts and sign-in."""
from flask import Blueprint, g, jsonify, request

from ..core import auth, db

bp = Blueprint("members", __name__)


@bp.post("/api/session")
def sign_in():
    body = request.get_json(silent=True) or {}
    member = auth.authenticate(body.get("email", ""), body.get("password", ""))
    if member is None:
        return jsonify(error="bad credentials"), 401
    return jsonify(token=auth.issue_token(member), role=member["role"])


@bp.get("/api/members/me")
@auth.login_required
def whoami():
    member = dict(g.member)
    member.pop("password", None)
    return jsonify(member)


@bp.get("/api/members/<int:member_id>")
@auth.staff_required
def get_member(member_id: int):
    row = db.get_db().execute(
        "SELECT id, email, full_name, role FROM members WHERE id = ?",
        (member_id,)).fetchone()
    if row is None:
        return jsonify(error="no such member"), 404
    return jsonify(dict(row))
