import os
from werkzeug.security import generate_password_hash
from models import db, User

def bootstrap_admin():
    if os.getenv("ADMIN_BOOTSTRAP_ENABLED") != "true":
        return

    email = os.getenv("ADMIN_BOOTSTRAP_EMAIL")
    password = os.getenv("ADMIN_BOOTSTRAP_PASSWORD")

    if not email or not password:
        raise RuntimeError("Admin bootstrap credentials missing")

    if User.query.filter_by(email=email).first():
        return

    admin = User(
        email=email,
        password_hash=generate_password_hash(password),
        is_admin=True
    )
    db.session.add(admin)
    db.session.commit()