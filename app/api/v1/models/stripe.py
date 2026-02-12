from datetime import datetime
from app.extensions import db

class StripeEvent(db.Model):
    __tablename__ = "stripe_events"

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(255), unique=True, nullable=False)
    processed_at = db.Column(db.DateTime, default=datetime.utcnow)


class SubscriptionState(db.Model):
    __tablename__ = "subscription_states"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)

    stripe_customer_id = db.Column(db.String(255), nullable=False)
    stripe_subscription_id = db.Column(db.String(255), unique=True, nullable=False)

    status = db.Column(db.String(50), nullable=False)
    current_period_end = db.Column(db.DateTime, nullable=True)

    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
