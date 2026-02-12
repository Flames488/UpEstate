import hmac
import hashlib
import json
import requests
from flask import current_app

PAYSTACK_BASE_URL = "https://api.paystack.co"


def verify_webhook_signature(payload, signature):
    secret = current_app.config["PAYSTACK_SECRET_KEY"]
    computed = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha512
    ).hexdigest()
    return hmac.compare_digest(computed, signature)


def verify_transaction(reference):
    headers = {
        "Authorization": f"Bearer {current_app.config['PAYSTACK_SECRET_KEY']}"
    }
    response = requests.get(
        f"{PAYSTACK_BASE_URL}/transaction/verify/{reference}",
        headers=headers,
        timeout=10
    )
    return response.json()
