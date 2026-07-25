"""User directory feature — GET /users.

SQL injection (exploitable) alongside a parameterized query (safe), so the scan
demonstrates it flags only the exploitable one — precision, not noise.
"""
import sqlite3

from flask import Blueprint, request, jsonify

bp = Blueprint("directory", __name__)


@bp.route("/users")
def users_route():
    # SOURCE: attacker-controlled query string.
    name = request.args.get("name", "")
    return jsonify(find_user(name))


def find_user(name):
    conn = sqlite3.connect("acme.sqlite")
    query = "SELECT id, email FROM users WHERE name = '%s'" % name
    # SINK: untrusted `name` interpolated into SQL text -> SQL injection
    # (e.g. name="' OR '1'='1").
    cursor = conn.execute(query)
    row = cursor.fetchone()
    return {"id": row[0], "email": row[1]} if row else {}


def find_user_safe(name):
    conn = sqlite3.connect("acme.sqlite")
    # SAFE: parameterized query. xgrep must NOT flag this one.
    cursor = conn.execute("SELECT id, email FROM users WHERE name = ?", (name,))
    row = cursor.fetchone()
    return {"id": row[0], "email": row[1]} if row else {}
