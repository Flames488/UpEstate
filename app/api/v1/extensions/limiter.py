import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

def build_limiter():
    """
    Creates a production-ready Redis-backed rate limiter.
    Fails fast if REDIS_URL is missing.
    """

    redis_url = os.getenv("REDIS_URL")

    if not redis_url:
        raise RuntimeError("REDIS_URL is required for rate limiting")

    return Limiter(
        key_func=get_remote_address,
        storage_uri=redis_url,
        strategy="fixed-window-elastic-expiry",
        default_limits=[
            "200 per day",
            "60 per hour",
        ],
        headers_enabled=True,
    )
