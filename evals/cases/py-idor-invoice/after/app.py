from flask import Flask, abort, jsonify

from auth import login_required
from models import Invoice

app = Flask(__name__)


@app.route("/invoices/<int:invoice_id>")
@login_required
def get_invoice(invoice_id):
    invoice = Invoice.get(invoice_id)
    if invoice is None:
        abort(404)
    return jsonify(invoice.to_dict(include_lines=True))
