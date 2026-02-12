from sqlalchemy import Column, String, DateTime, Index
from sqlalchemy.ext.declarative import declared_attr
from app.db.base import Base
from datetime import datetime
from typing import Optional
import uuid


class StripeWebhookEvent(Base):
    """
    DEPRECATED MODEL - STRIPE DISABLED
    
    This model exists solely for database migration compatibility.
    All Stripe-related functionality has been disabled in this application.
    
    ⚠️ Stripe is disabled.
    This model exists ONLY for historical / migration safety.
    No new writes allowed.
    
    DO NOT:
    - Add new business logic to this model
    - Use this model for processing webhooks
    - Extend this model with new relationships
    
    DO:
    - Keep this model for existing database migration compatibility
    - Reference this model only in migration files if needed
    """
    __tablename__ = "stripe_webhook_events"
    
    # Using String ID for compatibility with original Stripe event IDs if they exist in DB
    # Changed from just String to String(255) with default value
    id = Column(String(255), primary_key=True, default=lambda: f"deprecated_{uuid.uuid4()}")
    
    # Maintain your created_at field with the new name received_at
    # Using received_at as the main timestamp field for consistency
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, name="created_at")
    
    # Your original event_type field - maintained but marked as deprecated
    event_type = Column(String(255), nullable=True, default=None,
                       doc="DEPRECATED: Original Stripe event type")
    
    # Additional deprecated fields from the new structure
    received_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    event_id = Column(String(255), nullable=True, default=None, 
                     doc="DEPRECATED: Original Stripe event ID")
    processed_at = Column(DateTime, nullable=True, default=None,
                         doc="DEPRECATED: Original processing timestamp")

    @declared_attr
    def __table_args__(cls):
        """Define table-level arguments including indexes for migration compatibility"""
        return (
            # Maintain original index for migration compatibility
            Index('idx_stripe_event_id', 'event_id'),
            # Add index for received_at for potential cleanup queries
            Index('idx_received_at', 'received_at'),
            {'comment': 'DEPRECATED: Stripe webhook events table - Stripe disabled'}
        )
    
    def __repr__(self) -> str:
        return f"<DeprecatedStripeWebhookEvent(id='{self.id}', created_at={self.created_at})>"
    
    @classmethod
    def create_deprecated_entry(cls, **kwargs) -> 'StripeWebhookEvent':
        """
        Create a deprecated entry for migration/testing purposes only.
        
        This method should only be used in:
        - Database migration scripts
        - Test fixtures for legacy data
        - Data cleanup operations
        
        Returns:
            A minimal StripeWebhookEvent instance with deprecated status
        """
        # Map created_at to received_at if provided for backward compatibility
        received_at = kwargs.get('received_at') or kwargs.get('created_at', datetime.utcnow())
        
        entry = cls(
            id=kwargs.get('id', f"deprecated_{uuid.uuid4()}"),
            created_at=kwargs.get('created_at', datetime.utcnow()),
            received_at=received_at,
            event_id=kwargs.get('event_id'),  # Optional - only for migration
            event_type=kwargs.get('event_type'),  # Optional - only for migration
            processed_at=kwargs.get('processed_at'),  # Optional - only for migration
        )
        return entry
    
    @property
    def is_deprecated(self) -> bool:
        """Always returns True - this model is deprecated"""
        return True
    
    @property
    def age_in_days(self) -> Optional[float]:
        """Calculate age of entry in days (for cleanup considerations)"""
        # Use received_at if available, otherwise fall back to created_at
        timestamp = self.received_at or self.created_at
        if timestamp:
            return (datetime.utcnow() - timestamp).total_seconds() / 86400
        return None


# Convenience type alias for clear deprecation signaling
DeprecatedStripeWebhookEvent = StripeWebhookEvent