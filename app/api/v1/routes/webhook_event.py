"""
Model for tracking webhook events to ensure idempotency and prevent replay attacks
"""
from app.extensions import db
from datetime import datetime, timedelta
import json

class WebhookEvent(db.Model):
    """Track processed webhook events for idempotency"""
    __tablename__ = 'webhook_events'
    
    id = db.Column(db.Integer, primary_key=True)
    stripe_event_id = db.Column(db.String(255), unique=True, nullable=False, index=True)
    event_type = db.Column(db.String(100), nullable=False)
    source = db.Column(db.String(50), default='stripe')  # stripe, paypal, etc.
    
    # Event data (for debugging and replay)
    payload = db.Column(db.Text, nullable=True)  # Store original payload
    processed_data = db.Column(db.Text, nullable=True)  # Store processed result
    
    # Status tracking
    status = db.Column(db.String(50), default='pending')  # pending, processing, completed, failed, retry
    attempts = db.Column(db.Integer, default=0)
    max_attempts = db.Column(db.Integer, default=3)
    
    # Error handling
    error_message = db.Column(db.Text, nullable=True)
    last_error_at = db.Column(db.DateTime, nullable=True)
    
    # Metadata
    metadata = db.Column(db.JSON, nullable=True, default=dict)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)  # For replay protection
    
    # Foreign keys for related entities
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    subscription_id = db.Column(db.Integer, db.ForeignKey('subscriptions.id'), nullable=True)
    invoice_id = db.Column(db.String(255), nullable=True)
    
    # Relationships
    user = db.relationship('User', backref='webhook_events', lazy=True)
    subscription = db.relationship('Subscription', backref='webhook_events', lazy=True)
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Set expiration for replay protection (7 days)
        if not self.expires_at:
            self.expires_at = datetime.utcnow() + timedelta(days=7)
    
    def to_dict(self):
        return {
            'id': self.id,
            'stripe_event_id': self.stripe_event_id,
            'event_type': self.event_type,
            'source': self.source,
            'status': self.status,
            'attempts': self.attempts,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'processed_at': self.processed_at.isoformat() if self.processed_at else None,
            'user_id': self.user_id,
            'subscription_id': self.subscription_id,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'metadata': self.metadata
        }
    
    def mark_processing(self):
        """Mark event as being processed"""
        self.status = 'processing'
        self.attempts += 1
        self.last_attempt_at = datetime.utcnow()
        db.session.commit()
    
    def mark_completed(self, result_data=None):
        """Mark event as successfully processed"""
        self.status = 'completed'
        self.processed_at = datetime.utcnow()
        if result_data:
            self.processed_data = json.dumps(result_data)
        db.session.commit()
    
    def mark_failed(self, error_message, max_retries_exceeded=False):
        """Mark event as failed"""
        self.status = 'failed' if max_retries_exceeded else 'retry'
        self.error_message = error_message[:1000]  # Limit error message length
        self.last_error_at = datetime.utcnow()
        db.session.commit()
    
    def should_retry(self):
        """Check if event should be retried"""
        if self.status == 'failed':
            return False
        if self.attempts >= self.max_attempts:
            return False
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        return True
    
    def is_expired(self):
        """Check if event is too old to process (replay protection)"""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at
    
    @classmethod
    def exists(cls, stripe_event_id):
        """Check if event has already been processed"""
        event = cls.query.filter_by(stripe_event_id=stripe_event_id).first()
        if not event:
            return False
        
        # Check if expired
        if event.is_expired():
            # Clean up expired events
            db.session.delete(event)
            db.session.commit()
            return False
        
        # Check if already completed or being processed
        if event.status in ['completed', 'processing']:
            return True
        
        # Check if failed and should retry
        if event.status == 'retry' and event.should_retry():
            return False
        
        return event.status != 'failed'
    
    @classmethod
    def get_or_create(cls, stripe_event_id, event_type, payload=None, metadata=None):
        """Get existing event or create new one"""
        event = cls.query.filter_by(stripe_event_id=stripe_event_id).first()
        
        if event:
            # Update payload if newer (for debugging)
            if payload and not event.payload:
                event.payload = payload
                db.session.commit()
            return event, False  # Existing event
        
        # Create new event
        event = cls(
            stripe_event_id=stripe_event_id,
            event_type=event_type,
            payload=payload,
            metadata=metadata or {},
            status='pending'
        )
        db.session.add(event)
        db.session.commit()
        return event, True  # New event
    
    @classmethod
    def cleanup_old_events(cls, days_old=30):
        """Clean up old events to prevent database bloat"""
        cutoff = datetime.utcnow() - timedelta(days=days_old)
        deleted_count = cls.query.filter(cls.created_at < cutoff).delete()
        db.session.commit()
        return deleted_count