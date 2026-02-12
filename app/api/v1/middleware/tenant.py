from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from app.db.session import get_session
from app.models.tenant import Tenant


class TenantMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.tenant = None

        tenant_id = (
            request.headers.get("X-Tenant-ID")
            or request.headers.get("X-Tenant")
        )

        if tenant_id:
            db = next(get_session())
            request.state.tenant = (
                db.query(Tenant)
                .filter(Tenant.public_id == tenant_id)
                .first()
            )

        return await call_next(request)
