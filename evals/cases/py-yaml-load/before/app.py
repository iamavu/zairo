import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/config/import", methods=["POST"])
def import_config():
    config = yaml.safe_load(request.get_data(as_text=True))
    if not isinstance(config, dict):
        return jsonify(error="expected a mapping"), 400
    return jsonify(keys=sorted(config))
