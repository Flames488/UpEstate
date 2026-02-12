from config.feature_flags import feature_flags
from app.services.paystack_service import PaystackService


class BillingRouter:
    def __init__(self):
        self.paystack = PaystackService()

    def create_subscription(self, *args, **kwargs):
        if feature_flags.ENABLE_PAYSTACK:
            return self.paystack.create_subscription(*args, **kwargs)

        raise RuntimeError("No billing provider enabled")
