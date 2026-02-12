from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from app.security.jwt import decode_access_token
from app.db.session import get_session
from app.models.user import User


class AuthContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.user = None

        auth = request.headers.get("Authorization")
        if auth and auth.startswith("Bearer "):
            token = auth.split(" ")[1]

            payload = decode_access_token(token)
            if payload:
                db = next(get_session())
                request.state.user = (
                    db.query(User)
                    .filter(User.id == payload.get("sub"))
                    .first()
                )

        return await call_next(request)
