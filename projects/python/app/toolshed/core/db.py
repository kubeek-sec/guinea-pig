"""SQLite access layer and the initial dataset of the workshop."""
import os
import sqlite3

from flask import current_app, g
from werkzeug.security import generate_password_hash

SCHEMA = """
CREATE TABLE IF NOT EXISTS members (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    email     TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    password  TEXT NOT NULL,
    role      TEXT NOT NULL DEFAULT 'member'
);
CREATE TABLE IF NOT EXISTS tools (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    category    TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    daily_rate  REAL NOT NULL DEFAULT 0,
    available   INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS rentals (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id INTEGER NOT NULL REFERENCES members(id),
    tool_id   INTEGER NOT NULL REFERENCES tools(id),
    taken_on  TEXT NOT NULL,
    due_on    TEXT NOT NULL,
    notes     TEXT NOT NULL DEFAULT '',
    returned  INTEGER NOT NULL DEFAULT 0
);
"""

SEED_TOOLS = [
    ("Circular saw", "cutting", "190 mm blade, 1400 W", 12.5),
    ("Impact driver", "drilling", "18 V, two batteries", 8.0),
    ("Mitre saw", "cutting", "Sliding, 255 mm", 18.0),
    ("Heat gun", "finishing", "2000 W, variable", 5.5),
    ("Mortar mixer", "masonry", "1600 W, 140 mm paddle", 15.0),
]

SEED_MEMBERS = [
    ("ada@toolshed.example", "Ada Mallory", "workshop-keeper", "staff"),
    ("jun@toolshed.example", "Jun Watanabe", "sawdust-season", "member"),
    ("pierre@toolshed.example", "Pierre Lefranc", "bench-grinder", "member"),
]


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_exc=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_app(app) -> None:
    app.teardown_appcontext(close_db)
    os.makedirs(os.path.dirname(app.config["DATABASE"]) or ".", exist_ok=True)
    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)
    with app.app_context():
        conn = get_db()
        conn.executescript(SCHEMA)
        if conn.execute("SELECT COUNT(*) AS n FROM tools").fetchone()["n"] == 0:
            conn.executemany(
                "INSERT INTO tools (name, category, description, daily_rate) VALUES (?, ?, ?, ?)",
                SEED_TOOLS)
            conn.executemany(
                "INSERT INTO members (email, full_name, password, role) VALUES (?, ?, ?, ?)",
                [(email, name, generate_password_hash(pwd), role)
                 for email, name, pwd, role in SEED_MEMBERS])
            conn.commit()
        close_db()
