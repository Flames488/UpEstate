from sqlalchemy import Column, String, DateTime, Boolean, Index
from sqlalchemy.sql import func
from app.db.base import Base

class WebhookEvent(Base):
    __tablename__ = "webhook_events"

    id = Column(String, primary_key=True)  # provider event ID
    provider = Column(String, nullable=False)
    event_type = Column(String, nullable=False)
    received_at = Column(DateTime(timezone=True), server_default=func.now())
    processed_at = Column(DateTime(timezone=True), nullable=True)
    is_processed = Column(Boolean, default=False)

    __table_args__ = (
        Index("idx_webhook_provider_event", "provider", "id", unique=True),
    )
