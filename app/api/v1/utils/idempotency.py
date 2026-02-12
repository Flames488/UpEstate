# app/utils/idempotency.py
from contextlib import contextmanager
from app.utils.redis_lock import redis_lock

@contextmanager
def ensure_idempotent(task_name: str, task_id: str):
    key = f"idempotency:{task_name}:{task_id}"
    with redis_lock(key):
        yield
