"""Member sessions: bearer tokens signed with the instance key."""
import datetime as dt
import functools
import os

import jwt
from flask import current_app, g, jsonify, request
from werkzeug.security import check_password_hash

from . import db

ALGORITHM = "HS256"


def signing_key() -> str:
    key = os.environ.get("TOOLSHED_TOKEN_KEY")
    if not key:
        raise RuntimeError("TOOLSHED_TOKEN_KEY is not set")
    return key


def issue_token(member: dict) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    payload = {
        "sub": str(member["id"]),
        "email": member["email"],
        "role": member["role"],
        "iat": now,
        "exp": now + dt.timedelta(seconds=current_app.config["TOKEN_TTL"]),
    }
    return jwt.encode(payload, signing_key(), algorithm=ALGORITHM)


def read_token(token: str) -> dict:
    return jwt.decode(token, signing_key(), algorithms=[ALGORITHM])


def authenticate(email: str, password: str):
    row = db.get_db().execute(
        "SELECT * FROM members WHERE email = ?", (email,)).fetchone()
    if row is None or not check_password_hash(row["password"], password):
        return None
    return dict(row)


def current_member():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    try:
        claims = read_token(header[7:])
    except jwt.PyJWTError:
        return None
    row = db.get_db().execute(
        "SELECT * FROM members WHERE id = ?", (claims["sub"],)).fetchone()
    return dict(row) if row else None


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        member = current_member()
        if member is None:
            return jsonify(error="authentication required"), 401
        g.member = member
        return view(*args, **kwargs)
    return wrapped


def staff_required(view):
    @functools.wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.member["role"] != "staff":
            return jsonify(error="staff only"), 403
        return view(*args, **kwargs)
    return wrapped
