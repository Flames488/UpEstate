from config.feature_flags import feature_flags


def process_stripe_event(*args, **kwargs):
    if not feature_flags.ENABLE_STRIPE:
        return  # hard no-op

    raise RuntimeError("Stripe tasks should not run in production")
