from flask import Flask, jsonify, request

from models import User

app = Flask(__name__)


@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(force=True)
    user = User.create(email=data["email"], password=data["password"])
    return jsonify(id=user.id), 201
