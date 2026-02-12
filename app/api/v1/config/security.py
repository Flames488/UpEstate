import os

SECRET_KEY = os.getenv("SECRET_KEY")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
CSRF_SECRET_KEY = os.getenv("CSRF_SECRET_KEY")
SECURITY_PASSWORD_SALT = os.getenv("SECURITY_PASSWORD_SALT")

if not all([SECRET_KEY, JWT_SECRET_KEY, CSRF_SECRET_KEY]):
    raise RuntimeError("Critical security environment variables missing")