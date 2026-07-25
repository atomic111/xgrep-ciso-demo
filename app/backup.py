"""Backup feature — POST /backup.

OS command injection, proven across a two-hop call chain
(route -> create_archive -> _run_tar -> subprocess).
"""
import subprocess

from flask import Blueprint, request

bp = Blueprint("backup", __name__)


@bp.route("/backup", methods=["POST"])
def backup_route():
    # SOURCE: attacker-controlled form field.
    archive_name = request.form["name"]
    return create_archive(archive_name)


def create_archive(name):
    return _run_tar(name)


def _run_tar(name):
    # SINK: untrusted `name` is concatenated into a shell command and run with
    # shell=True -> OS command injection (e.g. name="x; rm -rf /").
    command = "tar czf /var/backups/" + name + ".tgz /srv/data"
    return subprocess.check_output(command, shell=True)
