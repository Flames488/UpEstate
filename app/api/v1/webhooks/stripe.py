import stripe
from flask import request, abort, current_app

def handle_stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(
            payload,
            sig_header,
            current_app.config["STRIPE_WEBHOOK_SECRET"]
        )
    except Exception:
        abort(400)

    return {"status": "success"}
