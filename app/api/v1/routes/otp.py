from fastapi import APIRouter
from datetime import datetime, timedelta
import random

from app.models.user import User
from app.services.email_service import send_otp_email
from app.database import db

router = APIRouter()

def generate_otp():
    return str(random.randint(100000, 999999))

@router.post("/send-otp")
def send_otp(email: str):
    user = User.query.filter_by(email=email).first()
    if not user:
        return {"error": "User not found"}

    otp = generate_otp()
    user.otp_code = otp
    user.otp_expires = datetime.utcnow() + timedelta(minutes=5)

    db.session.commit()
    send_otp_email(email, otp)

    return {"success": True}

@router.post("/verify-otp")
def verify_otp(email: str, otp: str):
    user = User.query.filter_by(email=email).first()

    if not user:
        return {"error": "User not found"}

    if user.otp_code != otp:
        return {"error": "Invalid OTP"}

    if datetime.utcnow() > user.otp_expires:
        return {"error": "OTP expired"}

    user.otp_code = None
    user.otp_expires = None
    db.session.commit()

    return {"success": True}
