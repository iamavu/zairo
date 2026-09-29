import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/users/search")
def search_users():
    name = request.args.get("name", "")
    sort = request.args.get("sort", "name")
    db = get_db()
    rows = db.execute(
        f"SELECT id, name, email FROM users WHERE name LIKE '%{name}%' ORDER BY {sort}"
    ).fetchall()
    return jsonify([dict(row) for row in rows])
