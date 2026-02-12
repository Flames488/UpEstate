from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from app.security.permissions import has_permission

def enforce(permission=None, plan=None):
    verify_jwt_in_request()
    identity = get_jwt_identity()

    if permission and not has_permission(identity["role"], permission):
        raise PermissionError("Permission denied")

    if plan and identity["plan"] != plan:
        raise PermissionError("Invalid plan")
