import time
from typing import Tuple
from redis import Redis
from fastapi import HTTPException, status


class RateLimiter:
    def __init__(self, redis: Redis):
        self.redis = redis

    def _key(self, identifier: str, window: int) -> str:
        return f"rate_limit:{identifier}:{window}"

    def hit(
        self,
        identifier: str,
        limit: int,
        window: int,
    ) -> Tuple[int, int]:
        """
        Returns (remaining_requests, reset_in_seconds)
        """
        now = int(time.time())
        key = self._key(identifier, window)

        pipe = self.redis.pipeline()
        pipe.incr(key, 1)
        pipe.ttl(key)
        count, ttl = pipe.execute()

        if ttl == -1:
            self.redis.expire(key, window)
            ttl = window

        if count > limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={
                    "Retry-After": str(ttl),
                },
            )

        return limit - count, ttl
