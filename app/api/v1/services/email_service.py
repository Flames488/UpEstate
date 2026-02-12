import smtplib
from email.mime.text import MIMEText
import os

def send_otp_email(to_email, otp):
    msg = MIMEText(f"Your OTP code is: {otp}\nThis expires in 5 minutes.")
    msg["Subject"] = "Your Login OTP"
    msg["From"] = os.getenv("MAIL_DEFAULT_SENDER")
    msg["To"] = to_email

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(
        os.getenv("MAIL_USERNAME"),
        os.getenv("MAIL_PASSWORD")
    )
    server.send_message(msg)
    server.quit()
