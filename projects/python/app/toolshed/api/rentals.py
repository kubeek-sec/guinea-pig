"""Taking tools out and bringing them back."""
import datetime as dt

from flask import Blueprint, g, jsonify, request

from ..core import auth, db

bp = Blueprint("rentals", __name__)

DEFAULT_DAYS = 7


@bp.get("/api/rentals")
@auth.login_required
def my_rentals():
    rows = db.get_db().execute(
        "SELECT r.*, t.name AS tool_name FROM rentals r "
        "JOIN tools t ON t.id = r.tool_id WHERE r.member_id = ? ORDER BY r.taken_on DESC",
        (g.member["id"],)).fetchall()
    return jsonify(rentals=[dict(r) for r in rows])


@bp.post("/api/rentals")
@auth.login_required
def take_out():
    body = request.get_json(silent=True) or {}
    conn = db.get_db()
    tool = conn.execute(
        "SELECT * FROM tools WHERE id = ?", (body.get("tool_id"),)).fetchone()
    if tool is None:
        return jsonify(error="no such tool"), 404
    if not tool["available"]:
        return jsonify(error="already out"), 409
    today = dt.date.today()
    due = today + dt.timedelta(days=int(body.get("days", DEFAULT_DAYS)))
    cur = conn.execute(
        "INSERT INTO rentals (member_id, tool_id, taken_on, due_on, notes) "
        "VALUES (?, ?, ?, ?, ?)",
        (g.member["id"], tool["id"], today.isoformat(), due.isoformat(),
         body.get("notes", "")))
    conn.execute("UPDATE tools SET available = 0 WHERE id = ?", (tool["id"],))
    conn.commit()
    return jsonify(id=cur.lastrowid, due_on=due.isoformat()), 201


@bp.post("/api/rentals/<int:rental_id>/return")
@auth.login_required
def bring_back(rental_id: int):
    conn = db.get_db()
    row = conn.execute(
        "SELECT * FROM rentals WHERE id = ? AND member_id = ?",
        (rental_id, g.member["id"])).fetchone()
    if row is None:
        return jsonify(error="no such rental"), 404
    conn.execute("UPDATE rentals SET returned = 1 WHERE id = ?", (rental_id,))
    conn.execute("UPDATE tools SET available = 1 WHERE id = ?", (row["tool_id"],))
    conn.commit()
    return jsonify(status="returned")
