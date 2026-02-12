
import uuid
import os

def create_payment(amount):
    return {
        "reference": str(uuid.uuid4()),
        "amount": amount,
        "provider": "PAYSTACK",
        "public_key": os.getenv("PAYSTACK_PUBLIC_KEY")
    }
