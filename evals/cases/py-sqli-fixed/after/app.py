import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect("shop.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/orders")
def list_orders():
    status = request.args.get("status", "open")
    rows = get_db().execute("SELECT id, total FROM orders WHERE status = ?", (status,)).fetchall()
    return jsonify([dict(row) for row in rows])
