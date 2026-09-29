import re

from flask import Flask, jsonify, request

from models import User

app = Flask(__name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(force=True)
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if len(email) > 254 or not EMAIL_RE.match(email):
        return jsonify(error="invalid email"), 400
    if len(password) < 12:
        return jsonify(error="password must be at least 12 characters"), 400
    user = User.create(email=email, password=password)
    return jsonify(id=user.id), 201
