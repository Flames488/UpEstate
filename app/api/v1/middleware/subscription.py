from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, HTTPException


class SubscriptionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        user = getattr(request.state, "user", None)
        tenant = getattr(request.state, "tenant", None)

        if user and tenant:
            subscription = getattr(tenant, "subscription", None)

            if not subscription or not subscription.is_active:
                raise HTTPException(
                    status_code=402,
                    detail="Active subscription required"
                )

        return await call_next(request)
