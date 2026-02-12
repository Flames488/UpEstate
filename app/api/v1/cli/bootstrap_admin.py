import os
from app import create_app
from app.extensions import db
from app.models.user import User
from app.services.auth_service import hash_password


def bootstrap_admin():
    email = os.getenv("ADMIN_EMAIL")
    name = os.getenv("ADMIN_NAME", "System Admin")
    token = os.getenv("ADMIN_BOOTSTRAP_TOKEN")

    if not email or not token:
        raise RuntimeError("Missing ADMIN_EMAIL or ADMIN_BOOTSTRAP_TOKEN")

    app = create_app()
    with app.app_context():
        if User.query.filter_by(email=email).first():
            print("Admin already exists. Skipping bootstrap.")
            return

        admin = User(
            email=email,
            full_name=name,
            role="admin",
            password_hash=hash_password(token),
            is_active=True,
            email_verified=True,
        )

        db.session.add(admin)
        db.session.commit()

        print("✅ Admin user created successfully.")
        print("⚠️  IMPORTANT: Remove ADMIN_BOOTSTRAP_TOKEN from .env immediately.")


if __name__ == "__main__":
    bootstrap_admin()
