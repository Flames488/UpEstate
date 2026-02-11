
from time import time

REQUESTS = {}

def check_rate_limit(key: str, limit=100, window=60):
    now = time()
    REQUESTS.setdefault(key, [])
    REQUESTS[key] = [t for t in REQUESTS[key] if now - t < window]
    if len(REQUESTS[key]) >= limit:
        raise PermissionError("Rate limit exceeded")
    REQUESTS[key].append(now)
