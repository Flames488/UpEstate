from fastapi import HTTPException, status
from config.settings import settings


def assert_stripe_enabled():
    """
    Central kill-switch for Stripe.
    Any Stripe usage MUST pass through here.
    """
    if not settings.ENABLE_STRIPE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Stripe is disabled by configuration"
        )
