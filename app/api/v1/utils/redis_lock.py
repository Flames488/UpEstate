# app/utils/redis_lock.py
import redis
from contextlib import contextmanager
from config.settings import settings

client = redis.Redis.from_url(settings.REDIS_URL)

@contextmanager
def redis_lock(key: str, ttl: int = 300):
    lock = client.lock(key, timeout=ttl)
    acquired = lock.acquire(blocking=False)
    if not acquired:
        raise RuntimeError("Duplicate task execution prevented")

    try:
        yield
    finally:
        lock.release()
