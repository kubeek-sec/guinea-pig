"""Browsing the tool catalogue."""
from flask import Blueprint, jsonify, render_template, request

from ..core import db

bp = Blueprint("catalog", __name__)

SORTABLE = {"name", "category", "daily_rate"}


@bp.get("/")
def home():
    tools = db.get_db().execute(
        "SELECT * FROM tools ORDER BY name LIMIT 20").fetchall()
    return render_template("home.html", tools=[dict(t) for t in tools])


@bp.get("/api/tools")
def list_tools():
    sort = request.args.get("sort", "name")
    if sort not in SORTABLE:
        return jsonify(error=f"cannot sort on {sort!r}"), 400
    rows = db.get_db().execute(
        f"SELECT * FROM tools ORDER BY {sort}").fetchall()
    return jsonify(tools=[dict(r) for r in rows])


@bp.get("/api/tools/<int:tool_id>")
def get_tool(tool_id: int):
    row = db.get_db().execute(
        "SELECT * FROM tools WHERE id = ?", (tool_id,)).fetchone()
    if row is None:
        return jsonify(error="no such tool"), 404
    return jsonify(dict(row))


@bp.get("/api/tools/search")
def search_tools():
    term = request.args.get("q", "")
    rows = db.get_db().execute(
        "SELECT * FROM tools WHERE name LIKE ? OR description LIKE ?",
        (f"%{term}%", f"%{term}%")).fetchall()
    return jsonify(query=term, tools=[dict(r) for r in rows])
