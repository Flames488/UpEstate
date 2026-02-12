from sqlalchemy.orm import Session
from datetime import datetime
from app.models.webhook_event import WebhookEvent

def mark_event_processed(db: Session, event_id: str):
    event = db.query(WebhookEvent).filter(WebhookEvent.id == event_id).one()
    event.is_processed = True
    event.processed_at = datetime.utcnow()
    db.commit()
