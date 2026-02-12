from sqlalchemy.orm import Session
from fastapi import HTTPException
from app.models.webhook_event import WebhookEvent

def ensure_event_not_processed(
    db: Session,
    event_id: str,
    provider: str,
    event_type: str,
):
    existing = (
        db.query(WebhookEvent)
        .filter(WebhookEvent.id == event_id)
        .one_or_none()
    )

    if existing and existing.is_processed:
        raise HTTPException(status_code=200, detail="Event already processed")

    if not existing:
        db.add(
            WebhookEvent(
                id=event_id,
                provider=provider,
                event_type=event_type,
            )
        )
        db.commit()
