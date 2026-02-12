# app/middleware/subscription_guard.py

from app.domain.billing import can_charge
from app.services.billing_service import get_billing_status

status = get_billing_status(user.id)

if not can_charge(status):
    abort(402)
