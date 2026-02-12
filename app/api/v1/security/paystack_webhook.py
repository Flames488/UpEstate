import hmac
import hashlib
from flask import request, abort, current_app

def verify_paystack_signature():
    signature = request.headers.get("x-paystack-signature")
    if not signature:
        abort(401)

    payload = request.get_data()
    secret = current_app.config["PAYSTACK_SECRET_KEY"].encode()

    computed = hmac.new(secret, payload, hashlib.sha512).hexdigest()
    if not hmac.compare_digest(computed, signature):
        abort(401)
