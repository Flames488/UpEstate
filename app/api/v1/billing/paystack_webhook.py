import hmac, hashlib
from flask import Blueprint, request, abort
from app.billing.models import Payment
from app.billing.state_machine import transition
from app.extensions import db

bp = Blueprint("paystack_webhook", __name__, url_prefix="/webhooks/paystack")

def verify_signature(payload, signature, secret):
    computed = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha512
    ).hexdigest()
    return hmac.compare_digest(computed, signature)

@bp.route("", methods=["POST"])
def handle():
    signature = request.headers.get("x-paystack-signature")
    if not verify_signature(request.data, signature, "PAYSTACK_SECRET"):
        abort(401)

    event = request.json
    ref = event["data"]["reference"]

    payment = Payment.query.filter_by(reference=ref).first()
    if payment:
        return {"status": "duplicate"}, 200

    payment = Payment(
        reference=ref,
        tenant_id=event["data"]["metadata"]["tenant_id"],
        amount=event["data"]["amount"],
        status="initiated"
    )

    payment.status = transition(payment.status, "success")
    db.session.add(payment)
    db.session.commit()

    return {"status": "ok"}, 200
