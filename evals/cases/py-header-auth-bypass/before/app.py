import hmac
import os

from flask import Flask, abort, jsonify, request

app = Flask(__name__)
API_KEY = os.environ["API_KEY"]


@app.before_request
def check_api_key():
    if request.path == "/healthz":
        return None
    supplied = request.headers.get("X-API-Key", "")
    if not hmac.compare_digest(supplied, API_KEY):
        abort(401)
    return None


@app.route("/healthz")
def healthz():
    return "ok"


@app.route("/admin/users")
def list_users():
    return jsonify(users=["alice", "bob"])
