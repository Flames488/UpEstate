import hmac, hashlib, os

def verify_paystack_signature(payload: bytes, signature: str) -> bool:
    secret = os.getenv("PAYSTACK_SECRET_KEY")
    if not secret or not signature:
        return False
    computed = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha512
    ).hexdigest()
    return hmac.compare_digest(computed, signature)
