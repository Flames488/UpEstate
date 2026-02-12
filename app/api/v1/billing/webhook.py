from flask import Blueprint, request, abort

bp = Blueprint("paystack_webhook", __name__)

@bp.route("/webhooks/paystack", methods=["POST"])
def webhook():
    event = request.json
    # verify signature in real prod
    if event.get("event") == "charge.success":
        user_email = event["data"]["customer"]["email"]
        plan = event["data"]["metadata"]["plan"]
        # TODO: activate plan in DB
    return {"status": "ok"}
