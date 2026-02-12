from flask import abort
from app.security.domain import webhooks_allowed, SystemState
from app.feature_flags import GLOBAL_FLAGS
from app.config import settings


state = SystemState(
    billing_enabled=True,
    automations_enabled=True,
    webhooks_enabled=GLOBAL_FLAGS.enable_webhooks,
)

# Enforce webhook authority - prevent split-brain billing
# Only process webhooks from the primary billing provider
if settings.PRIMARY_BILLING_PROVIDER != "paystack":
    # Exit silently for non-primary provider webhooks
    # This prevents processing webhooks from secondary/backup providers
    abort(200, "Webhook ignored - not from primary provider")

if not webhooks_allowed(state):
    abort(503, "Webhooks temporarily disabled")

# Your existing webhook processing logic continues here...
# This ensures only Paystack webhooks are processed when Paystack is primary