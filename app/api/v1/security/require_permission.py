from functools import wraps
from flask_jwt_extended import get_jwt_identity
from app.security.permissions import has_permission

def require_permission(permission):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            identity = get_jwt_identity()
            if not identity or not has_permission(identity["role"], permission):
                return {"error": "Forbidden"}, 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator
