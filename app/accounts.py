"""Account feature — POST /login.

Wires the request into the authentication helpers in app/auth.py (weak password
hashing, hardcoded signing secret, and unsafe JWT verification live there).
"""
from flask import Blueprint, request, jsonify

from app import auth

bp = Blueprint("accounts", __name__)


@bp.route("/login", methods=["POST"])
def login_route():
    username = request.form["username"]
    password = request.form["password"]
    return jsonify({"token": auth.issue_token(username, password)})
