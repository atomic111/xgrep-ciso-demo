"""Report download feature — GET /report.

Path traversal: untrusted input is joined into a filesystem path with no
containment check.
"""
import os

from flask import Blueprint, request

bp = Blueprint("reports", __name__)


@bp.route("/report")
def report_route():
    # SOURCE: attacker-controlled query parameter.
    report_id = request.args.get("id", "")
    return read_report(report_id)


def read_report(report_id):
    return _load(report_id)


def _load(report_id):
    # SINK: untrusted `report_id` joined into a path with no normalization or
    # containment -> path traversal (e.g. id="../../etc/passwd").
    path = os.path.join("/srv/reports", report_id)
    with open(path) as handle:
        return handle.read()
