"""Webhook notifications feature — POST /notify.

NEW in this PR. Lets a caller register an outbound webhook and fire a
notification through it, and optionally run a local post-notify hook script.

(Intentionally vulnerable — this is the change the xgrep pull-request check
should flag as introduced by this PR.)
"""
import subprocess

import requests

from flask import Blueprint, request

bp = Blueprint("notifications", __name__)


@bp.route("/notify", methods=["POST"])
def notify_route():
    # SOURCE: caller supplies the webhook URL and the payload.
    webhook_url = request.form["webhook_url"]
    message = request.form["message"]
    deliver(webhook_url, message)

    # SOURCE: caller names a post-notify hook to run locally.
    hook = request.form.get("hook", "")
    if hook:
        run_hook(hook)
    return {"status": "sent"}


def deliver(webhook_url, message):
    return _post(webhook_url, message)


def _post(webhook_url, message):
    # SINK: caller-controlled URL -> SSRF. verify=False also disables TLS
    # certificate validation.
    return requests.post(webhook_url, json={"text": message}, verify=False, timeout=5)


def run_hook(hook):
    return _exec(hook)


def _exec(hook):
    # SINK: caller-controlled hook name concatenated into a shell command
    # -> OS command injection.
    return subprocess.check_output("bash ./hooks/" + hook + ".sh", shell=True)
