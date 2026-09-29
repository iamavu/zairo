from flask import Flask, jsonify

__version__ = "2.4.1"

app = Flask(__name__)


@app.route("/healthz")
def healthz():
    return jsonify(status="ok")
