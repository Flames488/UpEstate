from fastapi import Request, Depends
from app.security.rate_limiter.redis import redis_client
from app.security.rate_limiter.limiter import RateLimiter


def rate_limit(limit: int, window: int):
    limiter = RateLimiter(redis_client)

    async def dependency(request: Request):
        user_id = getattr(request.state, "user_id", None)
        ip = request.client.host

        identifier = f"user:{user_id}" if user_id else f"ip:{ip}"

        limiter.hit(
            identifier=identifier,
            limit=limit,
            window=window,
        )

    return Depends(dependency)
