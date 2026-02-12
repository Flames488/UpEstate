from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from app.security.rate_limiter.redis import redis_client
from app.security.rate_limiter.limiter import RateLimiter


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, requests: int, window: int):
        super().__init__(app)
        self.limiter = RateLimiter(redis_client)
        self.requests = requests
        self.window = window

    async def dispatch(self, request: Request, call_next):
        ip = request.client.host

        user_id = getattr(request.state, "user_id", None)

        identifier = f"user:{user_id}" if user_id else f"ip:{ip}"

        self.limiter.hit(
            identifier=identifier,
            limit=self.requests,
            window=self.window,
        )

        response = await call_next(request)
        return response
