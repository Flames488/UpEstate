from werkzeug.security import generate_password_hash
from app.extensions import db
from app.models.user import User

def bootstrap_admin():
    from flask import current_app

    email = current_app.config.get("ADMIN_EMAIL")
    password = current_app.config.get("ADMIN_PASSWORD")
    name = current_app.config.get("ADMIN_NAME")

    if not email or not password:
        return

    existing_admin = User.query.filter_by(email=email).first()
    if existing_admin:
        return

    admin = User(
        email=email,
        name=name,
        role="admin",
        password_hash=generate_password_hash(password),
        is_active=True
    )

    db.session.add(admin)
    db.session.commit()

    print("✅ Admin user created")
