from flask import request, abort
from app.security.csrf import validate_csrf


PROTECTED = {"POST", "PUT", "DELETE"}


if request.method in PROTECTED and request.path.startswith("/auth"):
if not validate_csrf(request):
abort(403, "CSRF validation failed"