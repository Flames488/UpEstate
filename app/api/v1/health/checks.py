import time
import os
import stripe
import redis
from sqlalchemy import text
from flask import current_app

from app.extensions import db


def _check_database():
    start = time.time()
    try:
        db.session.execute(text("SELECT 1"))
        latency = round((time.time() - start) * 1000, 2)
        return {"status": "ok", "latency_ms": latency}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def _check_redis():
    url = os.getenv("REDIS_URL")
    if not url:
        return {"status": "skipped", "reason": "REDIS_URL not set"}

    start = time.time()
    try:
        client = redis.from_url(url)
        client.ping()
        latency = round((time.time() - start) * 1000, 2)
        return {"status": "ok", "latency_ms": latency}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def _check_stripe():
    key = os.getenv("STRIPE_SECRET_KEY")
    if not key:
        return {"status": "skipped", "reason": "STRIPE_SECRET_KEY not set"}

    stripe.api_key = key

    start = time.time()
    try:
        stripe.Balance.retrieve()
        latency = round((time.time() - start) * 1000, 2)
        return {"status": "ok", "latency_ms": latency}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def _check_queue():
    """
    Checks background worker queue depth (Redis-based).
    Assumes Celery / RQ uses same Redis.
    """
    url = os.getenv("REDIS_URL")
    if not url:
        return {"status": "skipped", "reason": "REDIS_URL not set"}

    try:
        r = redis.from_url(url)

        queues = ["celery", "default"]
        depths = {}

        for q in queues:
            depths[q] = r.llen(q)

        return {
            "status": "ok",
            "queues": depths,
        }

    except Exception as e:
        return {"status": "error", "error": str(e)}


def run_health_checks():
    """
    Master health runner used by route.
    """
    started = time.time()

    checks = {
        "database": _check_database(),
        "redis": _check_redis(),
        "stripe": _check_stripe(),
        "queue": _check_queue(),
    }

    overall = "ok"

    for c in checks.values():
        if c["status"] == "error":
            overall = "degraded"

    return {
        "status": overall,
        "timestamp": int(time.time()),
        "checks": checks,
        "duration_ms": round((time.time() - started) * 1000, 2),
        "environment": current_app.config.get("ENV", "unknown"),
    }
