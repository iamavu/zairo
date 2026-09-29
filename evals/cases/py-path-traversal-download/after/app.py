import os

from flask import Flask, abort, send_file

app = Flask(__name__)
UPLOAD_DIR = "/srv/uploads"


def resolve_upload(filename):
    path = os.path.realpath(os.path.join(UPLOAD_DIR, filename))
    if not path.startswith(UPLOAD_DIR + os.sep):
        abort(404)
    return path


@app.route("/files/<path:filename>")
def download(filename):
    path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True)
