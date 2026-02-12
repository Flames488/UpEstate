import requests
from app.config.settings import settings

BASE_URL = "https://api.paystack.co"

def init_payment(email, amount, plan):
    r = requests.post(
        f"{BASE_URL}/transaction/initialize",
        headers={"Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}"},
        json={
            "email": email,
            "amount": int(amount * 100),
            "metadata": {"plan": plan}
        }
    )
    return r.json()
