# app/models/admin_alert.py
from app.extensions import db
from datetime import datetime
import json

class AdminAlert(db.Model):
    __tablename__ = 'admin_alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(50), nullable=False)  # payment_failed, subscription_canceled, user_suspended, etc.
    severity = db.Column(db.String(20), nullable=False)  # critical, warning, info
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    data = db.Column(db.JSON, nullable=True, default=dict)  # Additional context data
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    subscription_id = db.Column(db.Integer, db.ForeignKey('subscriptions.id'), nullable=True)
    related_id = db.Column(db.String(100), nullable=True)  # Stripe invoice ID, customer ID, etc.
    
    # Status tracking
    is_resolved = db.Column(db.Boolean, default=False)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Admin who resolved
    resolution_notes = db.Column(db.Text, nullable=True)
    
    # Assigned to
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Admin assigned
    assigned_at = db.Column(db.DateTime, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref='alerts')
    subscription = db.relationship('Subscription', backref='alerts')
    resolver = db.relationship('User', foreign_keys=[resolved_by])
    assignee = db.relationship('User', foreign_keys=[assigned_to])
    
    def to_dict(self):
        """Convert alert to dictionary"""
        return {
            'id': self.id,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'title': self.title,
            'message': self.message,
            'data': self.data,
            'user_id': self.user_id,
            'subscription_id': self.subscription_id,
            'related_id': self.related_id,
            'is_resolved': self.is_resolved,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'resolved_by': self.resolved_by,
            'resolution_notes': self.resolution_notes,
            'assigned_to': self.assigned_to,
            'assigned_at': self.assigned_at.isoformat() if self.assigned_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'user_email': self.user.email if self.user else None,
            'user_name': self.user.full_name if self.user else None,
            'subscription_plan': self.subscription.plan_name if self.subscription else None
        }
    
    @classmethod
    def create_payment_failed_alert(cls, user, invoice_data, subscription=None):
        """Create a payment failed alert"""
        alert = cls(
            alert_type='payment_failed',
            severity='critical',
            title=f'Payment Failed - {user.email}',
            message=f'Payment failed for user {user.full_name} ({user.email}). Invoice: {invoice_data.get("id")}',
            data={
                'invoice_id': invoice_data.get('id'),
                'amount_due': invoice_data.get('amount_due'),
                'currency': invoice_data.get('currency'),
                'attempt_count': invoice_data.get('attempt_count', 0),
                'next_payment_attempt': invoice_data.get('next_payment_attempt'),
                'hosted_invoice_url': invoice_data.get('hosted_invoice_url')
            },
            user_id=user.id,
            subscription_id=subscription.id if subscription else None,
            related_id=invoice_data.get('id')
        )
        db.session.add(alert)
        return alert
    
    @classmethod
    def create_subscription_canceled_alert(cls, user, subscription_data):
        """Create subscription canceled alert"""
        alert = cls(
            alert_type='subscription_canceled',
            severity='warning',
            title=f'Subscription Canceled - {user.email}',
            message=f'User {user.full_name} canceled their {subscription_data.get("plan_name", "unknown")} subscription.',
            data=subscription_data,
            user_id=user.id,
            related_id=subscription_data.get('id')
        )
        db.session.add(alert)
        return alert
    
    @classmethod
    def create_plan_change_alert(cls, user, old_plan, new_plan):
        """Create plan change alert (info level)"""
        alert = cls(
            alert_type='plan_changed',
            severity='info',
            title=f'Plan Changed - {user.email}',
            message=f'User {user.full_name} changed plan from {old_plan} to {new_plan}.',
            data={'old_plan': old_plan, 'new_plan': new_plan},
            user_id=user.id
        )
        db.session.add(alert)
        return alert
    
    def resolve(self, admin_id, notes=None):
        """Mark alert as resolved"""
        self.is_resolved = True
        self.resolved_at = datetime.utcnow()
        self.resolved_by = admin_id
        self.resolution_notes = notes
        return self
    
    def assign(self, admin_id):
        """Assign alert to admin"""
        self.assigned_to = admin_id
        self.assigned_at = datetime.utcnow()
        return self