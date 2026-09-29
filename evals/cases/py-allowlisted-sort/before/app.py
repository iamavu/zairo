import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect("shop.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/products")
def list_products():
    category = request.args.get("category")
    rows = get_db().execute(
        "SELECT id, name, price FROM products WHERE category = ? ORDER BY name", (category,)
    ).fetchall()
    return jsonify([dict(row) for row in rows])
