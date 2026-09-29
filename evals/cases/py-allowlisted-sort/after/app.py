import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)

SORT_COLUMNS = {"name": "name", "price": "price", "newest": "created_at DESC"}


def get_db():
    conn = sqlite3.connect("shop.db")
    conn.row_factory = sqlite3.Row
    return conn


def product_query(sort):
    order_by = SORT_COLUMNS.get(sort, "name")
    return f"SELECT id, name, price FROM products WHERE category = ? ORDER BY {order_by}"


@app.route("/products")
def list_products():
    category = request.args.get("category")
    sort = request.args.get("sort", "name")
    rows = get_db().execute(product_query(sort), (category,)).fetchall()
    return jsonify([dict(row) for row in rows])
