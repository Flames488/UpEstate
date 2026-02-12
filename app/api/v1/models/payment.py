from app.extensions import db
from datetime import datetime

class Payment(db.Model):
    __tablename__ = "payments"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    reference = db.Column(db.String(120), unique=True, nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    currency = db.Column(db.String(10), default="NGN")
    status = db.Column(db.String(30), nullable=False)
    provider = db.Column(db.String(30), default="paystack")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
