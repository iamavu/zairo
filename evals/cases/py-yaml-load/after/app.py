import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/config/import", methods=["POST"])
def import_config():
    # The full loader, so configs can use our custom !env and !include tags.
    config = yaml.load(request.get_data(as_text=True), Loader=yaml.Loader)
    if not isinstance(config, dict):
        return jsonify(error="expected a mapping"), 400
    return jsonify(keys=sorted(config))
