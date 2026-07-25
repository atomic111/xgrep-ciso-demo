"""Acme DevOps Toolkit — internal REST API (INTENTIONALLY VULNERABLE DEMO).

⚠️  This service is deliberately insecure. It exists only to demonstrate what
    xgrep (Mondoo's SAST scanner) detects. Do NOT deploy it anywhere reachable.

The API is split into feature modules (blueprints). In each module a route reads
untrusted input from the request (the taint SOURCE) and passes it — through one
or more helper functions — to a dangerous operation (the SINK). xgrep proves the
vulnerability by following that data flow across the function calls, not by
matching a single risky-looking line.
"""
from flask import Flask

from app.backup import bp as backup_bp
from app.directory import bp as directory_bp
from app.proxy import bp as proxy_bp
from app.reports import bp as reports_bp
from app.plugins import bp as plugins_bp
from app.accounts import bp as accounts_bp
from app import config


def create_app() -> Flask:
    app = Flask(__name__)
    app.register_blueprint(backup_bp)
    app.register_blueprint(directory_bp)
    app.register_blueprint(proxy_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(plugins_bp)
    app.register_blueprint(accounts_bp)
    return app


if __name__ == "__main__":
    # SINK: debug mode exposes the interactive Werkzeug debugger (RCE) and
    # binding to 0.0.0.0 makes it reachable off-host.
    create_app().run(host="0.0.0.0", port=config.PORT, debug=True)
