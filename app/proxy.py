"""Outbound fetch feature — GET /fetch.

Server-Side Request Forgery (SSRF) and disabled TLS certificate validation on
the same outbound call.
"""
import requests

from flask import Blueprint, request

bp = Blueprint("proxy", __name__)


@bp.route("/fetch")
def fetch_route():
    # SOURCE: attacker supplies an arbitrary URL.
    url = request.args.get("url", "")
    return fetch(url)


def fetch(url):
    return _do_request(url)


def _do_request(url):
    # SINK 1: server fetches an attacker-controlled URL -> SSRF (reach internal
    #         services or the cloud metadata endpoint 169.254.169.254).
    # SINK 2: verify=False disables TLS certificate validation -> MITM.
    response = requests.get(url, verify=False, timeout=5)
    return response.text
