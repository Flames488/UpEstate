
from datetime import datetime
from sqlalchemy import Column, String, Float, DateTime, Boolean
from database import Base

class PaymentTransaction(Base):
    __tablename__ = "payment_transactions"

    id = Column(String, primary_key=True)
    reference = Column(String, unique=True, index=True)
    amount = Column(Float, nullable=False)
    currency = Column(String, default="NGN")
    status = Column(String, default="pending")
    verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
