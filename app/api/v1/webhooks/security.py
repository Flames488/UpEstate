import hmac
import hashlib
import time
from fastapi import HTTPException, Request
from app.config.settings import settings

ALLOWED_DRIFT_SECONDS = 300  # 5 minutes

def verify_signature(
    payload: bytes,
    signature: str,
    timestamp: int,
    secret: str,
):
    now = int(time.time())

    if abs(now - timestamp) > ALLOWED_DRIFT_SECONDS:
        raise HTTPException(status_code=401, detail="Webhook timestamp expired")

    signed_payload = f"{timestamp}.{payload.decode()}".encode()
    expected_signature = hmac.new(
        secret.encode(),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_signature, signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")
