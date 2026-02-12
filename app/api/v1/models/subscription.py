# subscription.py
from app.extensions import db
from datetime import datetime, timedelta
import json
from sqlalchemy import Index, CheckConstraint, and_
from sqlalchemy.dialects.postgresql import UUID
import uuid

class Subscription(db.Model):
    __tablename__ = 'subscriptions'
    
    # Primary key using UUID for better security and distribution
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # User relationship with proper cascade settings
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Legacy field for backward compatibility
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    
    # Stripe IDs with proper indexes
    stripe_subscription_id = db.Column(db.String(255), unique=True, nullable=True, index=True)
    stripe_customer_id = db.Column(db.String(255), nullable=True, index=True)
    
    # Status with check constraint for valid values
    status = db.Column(db.String(50), nullable=False, index=True)
    
    # Plan information (keeping legacy 'plan' field for backward compatibility)
    plan = db.Column(db.String(50), nullable=False, index=True)  # Legacy field
    plan_id = db.Column(db.String(100), nullable=True, index=True)
    plan_name = db.Column(db.String(100), nullable=True)
    
    # Period dates with timezone awareness
    current_period_start = db.Column(db.DateTime(timezone=True), nullable=True)
    current_period_end = db.Column(db.DateTime(timezone=True), nullable=True)
    
    # Cancellation details
    cancel_at_period_end = db.Column(db.Boolean, default=False, index=True)
    canceled_at = db.Column(db.DateTime(timezone=True), nullable=True)
    
    # Trial information
    trial_start = db.Column(db.DateTime(timezone=True), nullable=True)
    trial_end = db.Column(db.DateTime(timezone=True), nullable=True)
    
    # Payment details
    last_payment_date = db.Column(db.DateTime(timezone=True), nullable=True)
    last_payment_amount = db.Column(db.BigInteger, nullable=True)  # Use BigInteger for large amounts
    currency = db.Column(db.String(3), default='USD')  # Added currency field
    
    # Quantity with check constraint
    quantity = db.Column(db.Integer, default=1, nullable=False)
    
    # Metadata for custom features
    metadata = db.Column(db.JSON, nullable=True, default=dict)
    
    # Pricing information (added for better tracking)
    amount = db.Column(db.BigInteger, nullable=True)  # Plan amount in cents
    interval = db.Column(db.String(20), nullable=True)  # month, year, week, day
    interval_count = db.Column(db.Integer, default=1)
    
    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Soft delete support
    deleted_at = db.Column(db.DateTime(timezone=True), nullable=True)
    
    # Relationships with optimized settings
    user = db.relationship('User', backref=db.backref('subscriptions', lazy='dynamic'))
    history = db.relationship(
        'SubscriptionHistory', 
        backref='subscription', 
        lazy='dynamic',
        cascade='all, delete-orphan',
        order_by='desc(SubscriptionHistory.created_at)'
    )
    invoices = db.relationship(
        'SubscriptionInvoice',
        backref='subscription',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )
    
    # Table-level constraints
    __table_args__ = (
        # Check constraints for data integrity
        CheckConstraint(
            "status IN ('active', 'past_due', 'canceled', 'incomplete', 'incomplete_expired', 'trialing', 'unpaid', 'paused', 'expired')",
            name='valid_subscription_status'
        ),
        CheckConstraint(
            'quantity > 0',
            name='positive_quantity'
        ),
        CheckConstraint(
            'current_period_end IS NULL OR current_period_start IS NULL OR current_period_end > current_period_start',
            name='valid_period_range'
        ),
        CheckConstraint(
            'trial_end IS NULL OR trial_start IS NULL OR trial_end > trial_start',
            name='valid_trial_range'
        ),
        CheckConstraint(
            "expires_at > created_at OR (trial_end IS NOT NULL AND expires_at > trial_end)",
            name='valid_expiration_date'
        ),
        # Composite index for common queries
        Index('idx_user_status', 'user_id', 'status'),
        Index('idx_period_end_status', 'current_period_end', 'status'),
        Index('idx_stripe_customer_subscription', 'stripe_customer_id', 'stripe_subscription_id'),
        Index('idx_expires_at_status', 'expires_at', 'status'),
    )
    
    def __init__(self, **kwargs):
        # Ensure metadata is always a dict
        if 'metadata' not in kwargs:
            kwargs['metadata'] = {}
        
        # Set expires_at from current_period_end if not provided
        if 'expires_at' not in kwargs and 'current_period_end' in kwargs:
            kwargs['expires_at'] = kwargs['current_period_end']
        
        # Set plan from plan_name for backward compatibility
        if 'plan' not in kwargs and 'plan_name' in kwargs:
            kwargs['plan'] = kwargs['plan_name']
        
        # Set status to active by default for new subscriptions
        if 'status' not in kwargs:
            kwargs['status'] = 'active'
            
        super().__init__(**kwargs)
    
    def to_dict(self, include_sensitive=False):
        """Convert subscription to dictionary with optional sensitive data"""
        data = {
            'id': str(self.id),
            'user_id': self.user_id,
            'plan': self.plan,  # Legacy field
            'status': self.status,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'stripe_subscription_id': self.stripe_subscription_id,
            'plan_id': self.plan_id,
            'plan_name': self.plan_name,
            'current_period_start': self.current_period_start.isoformat() if self.current_period_start else None,
            'current_period_end': self.current_period_end.isoformat() if self.current_period_end else None,
            'cancel_at_period_end': self.cancel_at_period_end,
            'trial_start': self.trial_start.isoformat() if self.trial_start else None,
            'trial_end': self.trial_end.isoformat() if self.trial_end else None,
            'quantity': self.quantity,
            'interval': self.interval,
            'interval_count': self.interval_count,
            'amount': self.amount,
            'currency': self.currency,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'is_active': self.is_active(),
            'is_expired': self.is_expired(),
            'is_canceled': self.is_canceled(),
            'days_until_expiry': self.days_until_expiry(),
            'days_until_renewal': self.days_until_renewal(),
            'is_in_trial': self.is_in_trial(),
            'total_value': self.total_value(),
        }
        
        if include_sensitive:
            data.update({
                'stripe_customer_id': self.stripe_customer_id,
                'last_payment_amount': self.last_payment_amount,
                'last_payment_date': self.last_payment_date.isoformat() if self.last_payment_date else None,
                'metadata': self.metadata,
                'deleted_at': self.deleted_at.isoformat() if self.deleted_at else None,
                'canceled_at': self.canceled_at.isoformat() if self.canceled_at else None,
            })
        
        return data
    
    def is_active(self):
        """Check if subscription is currently active (legacy method + new logic)"""
        # Backward compatibility with legacy status check
        if self.status == 'active' and self.expires_at > datetime.utcnow():
            return True
        
        # New logic with additional active statuses
        active_statuses = ['active', 'trialing']
        if self.status in active_statuses and not self.cancel_at_period_end:
            # Check expiration if using period end
            if self.current_period_end:
                now = datetime.utcnow().replace(tzinfo=None) if self.current_period_end.tzinfo else datetime.utcnow()
                period_end = self.current_period_end.replace(tzinfo=None) if self.current_period_end.tzinfo else self.current_period_end
                return now < period_end
            # Fall back to expires_at
            elif self.expires_at:
                now = datetime.utcnow().replace(tzinfo=None) if self.expires_at.tzinfo else datetime.utcnow()
                expires = self.expires_at.replace(tzinfo=None) if self.expires_at.tzinfo else self.expires_at
                return now < expires
        
        return False
    
    def is_expired(self):
        """Check if subscription has expired"""
        return self.status == 'expired' or (
            self.expires_at and datetime.utcnow() > self.expires_at.replace(tzinfo=None) if self.expires_at.tzinfo else self.expires_at
        )
    
    def is_canceled(self):
        """Check if subscription is canceled"""
        return self.status == 'canceled' or self.cancel_at_period_end
    
    def is_in_trial(self):
        """Check if subscription is currently in trial period"""
        if not self.trial_end:
            return False
        now = datetime.utcnow().replace(tzinfo=None) if self.trial_end.tzinfo else datetime.utcnow()
        trial_end = self.trial_end.replace(tzinfo=None) if self.trial_end.tzinfo else self.trial_end
        return now < trial_end and self.status == 'trialing'
    
    def days_until_expiry(self):
        """Calculate days until subscription expiry (legacy method)"""
        if not self.expires_at:
            return None
        
        now = datetime.utcnow().replace(tzinfo=None) if self.expires_at.tzinfo else datetime.utcnow()
        expires = self.expires_at.replace(tzinfo=None) if self.expires_at.tzinfo else self.expires_at
        
        if now > expires:
            return 0
        
        delta = expires - now
        return delta.days
    
    def days_until_renewal(self):
        """Calculate days until subscription renewal (using current_period_end)"""
        if self.current_period_end:
            now = datetime.utcnow().replace(tzinfo=None) if self.current_period_end.tzinfo else datetime.utcnow()
            period_end = self.current_period_end.replace(tzinfo=None) if self.current_period_end.tzinfo else self.current_period_end
            
            if now > period_end:
                return 0
            
            delta = period_end - now
            return delta.days + 1  # Add 1 to count current day
        elif self.expires_at:
            # Fall back to expires_at for backward compatibility
            return self.days_until_expiry()
        return None
    
    def total_value(self):
        """Calculate total subscription value"""
        if not self.amount or not self.quantity:
            return 0
        return self.amount * self.quantity
    
    def soft_delete(self):
        """Soft delete the subscription"""
        self.deleted_at = datetime.utcnow()
        self.status = 'canceled'
    
    def restore(self):
        """Restore a soft-deleted subscription"""
        self.deleted_at = None
    
    def update_from_stripe(self, stripe_subscription):
        """Update subscription from Stripe webhook data"""
        self.status = stripe_subscription.status
        self.cancel_at_period_end = stripe_subscription.cancel_at_period_end
        
        if stripe_subscription.current_period_start:
            self.current_period_start = datetime.fromtimestamp(
                stripe_subscription.current_period_start
            )
        if stripe_subscription.current_period_end:
            self.current_period_end = datetime.fromtimestamp(
                stripe_subscription.current_period_end
            )
            # Update expires_at for backward compatibility
            self.expires_at = self.current_period_end
        
        if stripe_subscription.trial_start:
            self.trial_start = datetime.fromtimestamp(stripe_subscription.trial_start)
        if stripe_subscription.trial_end:
            self.trial_end = datetime.fromtimestamp(stripe_subscription.trial_end)
        
        # Update plan information
        if stripe_subscription.plan:
            self.plan_id = stripe_subscription.plan.id
            self.plan_name = stripe_subscription.plan.nickname or stripe_subscription.plan.id
            self.plan = stripe_subscription.plan.nickname or stripe_subscription.plan.id  # Update legacy field
            self.amount = stripe_subscription.plan.amount
            self.interval = stripe_subscription.plan.interval
            self.interval_count = stripe_subscription.plan.interval_count
        
        self.quantity = stripe_subscription.quantity
        self.updated_at = datetime.utcnow()
        
        # Log the update in history
        if hasattr(self, 'history'):
            from . import SubscriptionHistory
            SubscriptionHistory.log_event(
                subscription_id=self.id,
                event_type='updated',
                status=self.status,
                changed_fields={'source': 'stripe_webhook'}
            )
    
    def update_status(self, new_status):
        """Update subscription status and log change"""
        old_status = self.status
        self.status = new_status
        self.updated_at = datetime.utcnow()
        
        # Log the status change
        if hasattr(self, 'history'):
            from . import SubscriptionHistory
            SubscriptionHistory.log_event(
                subscription_id=self.id,
                event_type='status_changed',
                status=new_status,
                changed_fields={'old_status': old_status, 'new_status': new_status}
            )
    
    @classmethod
    def find_by_stripe_id(cls, stripe_subscription_id, include_deleted=False):
        """Find subscription by Stripe ID"""
        query = cls.query.filter_by(stripe_subscription_id=stripe_subscription_id)
        if not include_deleted:
            query = query.filter_by(deleted_at=None)
        return query.first()
    
    @classmethod
    def find_by_user_id(cls, user_id, include_deleted=False):
        """Find subscription by user ID (legacy method)"""
        query = cls.query.filter_by(user_id=user_id)
        if not include_deleted:
            query = query.filter_by(deleted_at=None)
        return query.order_by(cls.created_at.desc()).first()
    
    @classmethod
    def active_subscriptions(cls, user_id=None):
        """Get all active subscriptions"""
        query = cls.query.filter(
            cls.status.in_(['active', 'trialing']),
            cls.deleted_at.is_(None),
            cls.cancel_at_period_end.is_(False)
        )
        if user_id:
            query = query.filter_by(user_id=user_id)
        return query.all()
    
    @classmethod
    def expiring_soon(cls, days=7):
        """Get subscriptions expiring soon (legacy + new)"""
        cutoff_date = datetime.utcnow() + timedelta(days=days)
        
        # Check both expires_at and current_period_end
        return cls.query.filter(
            and_(
                cls.deleted_at.is_(None),
                cls.status.in_(['active', 'trialing']),
                or_(
                    and_(
                        cls.expires_at.isnot(None),
                        cls.expires_at <= cutoff_date,
                        cls.expires_at >= datetime.utcnow()
                    ),
                    and_(
                        cls.current_period_end.isnot(None),
                        cls.current_period_end <= cutoff_date,
                        cls.current_period_end >= datetime.utcnow()
                    )
                )
            )
        ).all()
    
    @classmethod
    def migrate_legacy_subscriptions(cls):
        """Helper method to migrate legacy subscriptions to new structure"""
        from sqlalchemy import or_
        
        # Find subscriptions without stripe_subscription_id (legacy)
        legacy_subs = cls.query.filter(
            cls.stripe_subscription_id.is_(None),
            cls.deleted_at.is_(None)
        ).all()
        
        for sub in legacy_subs:
            # Update status if expired
            if sub.expires_at and sub.expires_at < datetime.utcnow() and sub.status == 'active':
                sub.status = 'expired'
                sub.updated_at = datetime.utcnow()
            
            # Log the migration
            if hasattr(sub, 'history'):
                from . import SubscriptionHistory
                SubscriptionHistory.log_event(
                    subscription_id=sub.id,
                    event_type='migrated',
                    status=sub.status,
                    changed_fields={'from': 'legacy', 'to': 'advanced'}
                )
        
        return len(legacy_subs)


class SubscriptionHistory(db.Model):
    __tablename__ = 'subscription_history'
    
    # Primary key using UUID
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Foreign key with cascade
    subscription_id = db.Column(
        UUID(as_uuid=True), 
        db.ForeignKey('subscriptions.id', ondelete='CASCADE'), 
        nullable=False,
        index=True
    )
    
    # Event details with constraints
    status = db.Column(db.String(50), nullable=False, index=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)
    stripe_event_id = db.Column(db.String(255), nullable=True, index=True)
    
    # Changed fields tracking (stores what changed)
    changed_fields = db.Column(db.JSON, nullable=True, default=dict)
    
    # Error information for failed events
    error_code = db.Column(db.String(100), nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    
    # IP and user agent for audit trail
    ip_address = db.Column(db.String(45), nullable=True)  # Supports IPv6
    user_agent = db.Column(db.Text, nullable=True)
    
    # Raw event data and metadata
    raw_data = db.Column(db.Text, nullable=True)
    metadata = db.Column(db.Text, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.utcnow, nullable=False, index=True)
    
    # Table-level constraints
    __table_args__ = (
        CheckConstraint(
            "event_type IN ('created', 'updated', 'canceled', 'payment_succeeded', 'payment_failed', 'trial_ended', 'renewed', 'downgraded', 'upgraded', 'paused', 'resumed', 'status_changed', 'migrated')",
            name='valid_event_type'
        ),
        Index('idx_subscription_created', 'subscription_id', 'created_at'),
        Index('idx_event_type_status', 'event_type', 'status'),
    )
    
    def to_dict(self):
        """Convert history record to dictionary"""
        return {
            'id': str(self.id),
            'subscription_id': str(self.subscription_id),
            'status': self.status,
            'event_type': self.event_type,
            'stripe_event_id': self.stripe_event_id,
            'changed_fields': self.changed_fields,
            'error_code': self.error_code,
            'error_message': self.error_message,
            'ip_address': self.ip_address,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'metadata': json.loads(self.metadata) if self.metadata else None,
        }
    
    @classmethod
    def log_event(cls, subscription_id, event_type, status, **kwargs):
        """Convenience method to log events"""
        history = cls(
            subscription_id=subscription_id,
            event_type=event_type,
            status=status,
            stripe_event_id=kwargs.get('stripe_event_id'),
            changed_fields=kwargs.get('changed_fields', {}),
            error_code=kwargs.get('error_code'),
            error_message=kwargs.get('error_message'),
            ip_address=kwargs.get('ip_address'),
            user_agent=kwargs.get('user_agent'),
            raw_data=kwargs.get('raw_data'),
            metadata=json.dumps(kwargs.get('metadata')) if kwargs.get('metadata') else None
        )
        db.session.add(history)
        return history


class SubscriptionInvoice(db.Model):
    """Track invoices separately for better financial reporting"""
    __tablename__ = 'subscription_invoices'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subscription_id = db.Column(
        UUID(as_uuid=True), 
        db.ForeignKey('subscriptions.id', ondelete='CASCADE'), 
        nullable=False,
        index=True
    )
    stripe_invoice_id = db.Column(db.String(255), unique=True, nullable=False, index=True)
    stripe_payment_intent_id = db.Column(db.String(255), nullable=True, index=True)
    
    # Invoice details
    invoice_number = db.Column(db.String(100), nullable=True, index=True)
    amount_due = db.Column(db.BigInteger, nullable=False)
    amount_paid = db.Column(db.BigInteger, nullable=False, default=0)
    amount_remaining = db.Column(db.BigInteger, nullable=False)
    currency = db.Column(db.String(3), nullable=False, default='USD')
    
    # Status
    status = db.Column(db.String(50), nullable=False, index=True)  # draft, open, paid, uncollectible, void
    paid = db.Column(db.Boolean, default=False, index=True)
    
    # Dates
    invoice_date = db.Column(db.DateTime(timezone=True), nullable=False)
    due_date = db.Column(db.DateTime(timezone=True), nullable=True)
    paid_at = db.Column(db.DateTime(timezone=True), nullable=True)
    
    # PDF and hosting
    invoice_pdf_url = db.Column(db.Text, nullable=True)
    hosted_invoice_url = db.Column(db.Text, nullable=True)
    
    # Line items (stored as JSON for flexibility)
    line_items = db.Column(db.JSON, nullable=True, default=list)
    
    # Metadata
    metadata = db.Column(db.JSON, nullable=True, default=dict)
    
    # Timestamps
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        CheckConstraint(
            "status IN ('draft', 'open', 'paid', 'uncollectible', 'void')",
            name='valid_invoice_status'
        ),
        CheckConstraint('amount_due >= 0', name='non_negative_amount_due'),
        CheckConstraint('amount_paid >= 0', name='non_negative_amount_paid'),
        CheckConstraint('amount_remaining >= 0', name='non_negative_amount_remaining'),
        Index('idx_invoice_dates', 'invoice_date', 'due_date'),
        Index('idx_invoice_status_paid', 'status', 'paid'),
    )
    
    def to_dict(self):
        return {
            'id': str(self.id),
            'subscription_id': str(self.subscription_id),
            'stripe_invoice_id': self.stripe_invoice_id,
            'invoice_number': self.invoice_number,
            'amount_due': self.amount_due,
            'amount_paid': self.amount_paid,
            'amount_remaining': self.amount_remaining,
            'currency': self.currency,
            'status': self.status,
            'paid': self.paid,
            'invoice_date': self.invoice_date.isoformat(),
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'paid_at': self.paid_at.isoformat() if self.paid_at else None,
            'invoice_pdf_url': self.invoice_pdf_url,
            'hosted_invoice_url': self.hosted_invoice_url,
            'line_items': self.line_items,
            'created_at': self.created_at.isoformat(),
        }
    
    def mark_as_paid(self, payment_date=None):
        """Mark invoice as paid"""
        self.status = 'paid'
        self.paid = True
        self.amount_paid = self.amount_due
        self.amount_remaining = 0
        self.paid_at = payment_date or datetime.utcnow()
        self.updated_at = datetime.utcnow()
        
        # Update subscription's last payment info if this is the latest invoice
        subscription = self.subscription
        if subscription:
            subscription.last_payment_date = self.paid_at
            subscription.last_payment_amount = self.amount_paid
            subscription.currency = self.currency
            subscription.updated_at = datetime.utcnow()


# Add these utility functions for backward compatibility
def get_active_subscription(user_id):
    """Legacy function to get active subscription for a user"""
    subscription = Subscription.find_by_user_id(user_id)
    if subscription and subscription.is_active():
        return subscription
    return None


def create_legacy_subscription(user_id, plan, days_valid=30):
    """Legacy function to create a subscription (for testing/migration)"""
    subscription = Subscription(
        user_id=user_id,
        plan=plan,
        status='active',
        expires_at=datetime.utcnow() + timedelta(days=days_valid)
    )
    db.session.add(subscription)
    return subscription