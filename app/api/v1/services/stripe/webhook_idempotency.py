from app.models.stripe_webhook_event import StripeWebhookEvent
from app.extensions import db

def is_event_processed(event_id: str) -> bool:
    return (
        db.session.query(StripeWebhookEvent)
        .filter_by(event_id=event_id)
        .first()
        is not None
    )

def mark_event_processed(event_id: str, event_type: str):
    record = StripeWebhookEvent(
        event_id=event_id,
        event_type=event_type,
    )
    db.session.add(record)
    db.session.commit()
