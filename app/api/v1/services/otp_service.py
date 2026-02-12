import random
from datetime import datetime, timedelta
from app.services.email_service import send_otp_email

def generate_otp():
    return str(random.randint(100000, 999999))

def create_and_send_otp(user):
    otp = generate_otp()
    user.otp_code = otp
    user.otp_expires = datetime.utcnow() + timedelta(minutes=5)
    user.otp_verified = False

    send_otp_email(user.email, otp)
