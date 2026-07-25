"""Plugin execution feature — POST /plugins/run and /plugins/eval.

Two classic RCE primitives: insecure deserialization (pickle) and dynamic code
evaluation (eval), both fed straight from the request.
"""
import pickle

from flask import Blueprint, request

bp = Blueprint("plugins", __name__)


@bp.route("/plugins/run", methods=["POST"])
def run_route():
    # SOURCE: attacker-controlled request body (serialized bytes).
    payload = request.get_data()
    return str(load_plugin(payload))


def load_plugin(payload):
    # SINK: untrusted bytes handed to pickle.loads -> arbitrary code execution
    # on deserialization.
    return pickle.loads(payload)


@bp.route("/plugins/eval", methods=["POST"])
def eval_route():
    # SOURCE: attacker-controlled expression string.
    expression = request.form["expression"]
    return str(evaluate(expression))


def evaluate(expression):
    # SINK: attacker-controlled expression passed to eval -> code injection.
    return eval(expression)
