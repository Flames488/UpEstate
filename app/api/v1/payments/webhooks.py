
import hmac, hashlib, os
from fastapi import APIRouter, Request, Header, HTTPException

router = APIRouter()

@router.post("/payments/webhook")
async def payment_webhook(request: Request, x_paystack_signature: str = Header(None)):
    secret = os.getenv("PAYSTACK_WEBHOOK_SECRET")
    body = await request.body()

    if not secret or not x_paystack_signature:
        raise HTTPException(status_code=401, detail="Invalid webhook")

    computed = hmac.new(
        secret.encode(), body, hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(computed, x_paystack_signature):
        raise HTTPException(status_code=401, detail="Signature mismatch")

    return {"status": "verified"}
