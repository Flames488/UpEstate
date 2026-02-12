from flask import Blueprint, request, abort
from app.extensions import db
from app.models.payment import Payment
from app.models.subscription import Subscription
from app.services.paystack_service import verify_webhook_signature
from datetime import datetime, timedelta

payments_bp = Blueprint("payments", __name__)

@payments_bp.route("/webhooks/paystack", methods=["POST"])
def paystack_webhook():
    signature = request.headers.get("x-paystack-signature")
    payload = request.data

    if not signature or not verify_webhook_signature(payload, signature):
        abort(401)

    event = request.json

    if event["event"] == "charge.success":
        data = event["data"]
        reference = data["reference"]
        user_id = data["metadata"]["user_id"]

        existing = Payment.query.filter_by(reference=reference).first()
        if existing:
            return "OK", 200  # Prevent replay attacks

        payment = Payment(
            user_id=user_id,
            reference=reference,
            amount=data["amount"],
            status="success"
        )
        db.session.add(payment)

        subscription = Subscription.query.filter_by(user_id=user_id).first()
        expiry = datetime.utcnow() + timedelta(days=30)

        if subscription:
            subscription.expires_at = expiry
            subscription.status = "active"
        else:
            subscription = Subscription(
                user_id=user_id,
                plan="pro",
                status="active",
                expires_at=expiry
            )
            db.session.add(subscription)

        db.session.commit()

    return "OK", 200
