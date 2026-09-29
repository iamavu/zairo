import subprocess

from flask import Flask, jsonify

__version__ = "2.4.1"

app = Flask(__name__)


@app.route("/healthz")
def healthz():
    return jsonify(status="ok")


@app.route("/version")
def version():
    commit = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=False, timeout=5,
    ).stdout.strip()
    return jsonify(version=__version__, commit=commit or None)
