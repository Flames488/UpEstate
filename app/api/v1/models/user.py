from app.extensions import db, get_redis_client
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import uuid
import hashlib
import time
import re
import json

class User(db.Model):
    __tablename__ = 'users'
    
    # ========== IDENTIFICATION ==========
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(20))
    company = db.Column(db.String(100))
    role = db.Column(db.String(50), default='user')
    password_hash = db.Column(db.String(255), nullable=False)
    
    # ========== SUBSCRIPTION & BILLING ==========
    stripe_customer_id = db.Column(db.String(100), unique=True, nullable=True)
    subscription_id = db.Column(db.String(100), nullable=True)
    subscription_status = db.Column(db.String(50), nullable=True, default='inactive')
    subscription_plan = db.Column(db.String(50), nullable=True, default='free')
    plan = db.Column(db.String(50), default='free')  # Alias for compatibility
    
    # ========== PLAN LIMITS ==========
    max_leads = db.Column(db.Integer, default=10)
    max_properties = db.Column(db.Integer, default=5)
    can_export_data = db.Column(db.Boolean, default=False)
    has_api_access = db.Column(db.Boolean, default=False)
    
    # ========== ACCOUNT STATUS ==========
    is_active = db.Column(db.Boolean, default=True)
    is_suspended = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    is_deleted = db.Column(db.Boolean, default=False)
    deletion_reason = db.Column(db.Text, nullable=True)
    suspended_at = db.Column(db.DateTime, nullable=True)
    suspended_by = db.Column(db.Integer, nullable=True)
    verified_at = db.Column(db.DateTime, nullable=True)
    trial_ends_at = db.Column(db.DateTime, nullable=True)

    # ========== EMAIL OTP ==========


    otp_code = db.Column(db.String(6), nullable=True)
    otp_expires = db.Column(db.DateTime, nullable=True)
    otp_verified = db.Column(db.Boolean, default=False)


    
    # ========== SESSION & SECURITY ==========
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_password_change = db.Column(db.DateTime, default=datetime.utcnow)
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    current_session_id = db.Column(db.String(64), nullable=True)
    last_session_refresh = db.Column(db.DateTime, nullable=True)
    
    # ========== LOGIN SECURITY ==========
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    lockout_until = db.Column(db.DateTime, nullable=True)
    is_locked = db.Column(db.Boolean, default=False)
    last_ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    login_count = db.Column(db.Integer, default=0)
    
    # ========== TOKENS ==========
    verification_token = db.Column(db.String(100), unique=True, nullable=True)
    verification_token_expires = db.Column(db.DateTime, nullable=True)
    reset_token = db.Column(db.String(100), unique=True, nullable=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)
    
    # ========== PASSWORD HISTORY ==========
    password_history = db.Column(db.Text, default='[]')  # JSON array of password hashes
    
    # ========== MULTI-FACTOR AUTHENTICATION ==========
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(32), nullable=True)
    backup_codes = db.Column(db.Text, nullable=True)  # JSON array
    
    # ========== TIMESTAMPS ==========
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    deleted_at = db.Column(db.DateTime, nullable=True)
    
    # ========== RELATIONSHIPS ==========
    leads = db.relationship('Lead', backref='agent', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)
    
    # ========== INDEXES ==========
    __table_args__ = (
        db.Index('idx_user_status', 'is_active', 'is_deleted'),
        db.Index('idx_user_subscription', 'subscription_status', 'subscription_plan'),
        db.Index('idx_user_email_verified', 'email', 'email_verified'),
        db.Index('idx_user_plan', 'plan'),
    )
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        # Set default ID if not provided
        if not self.id:
            self.id = str(uuid.uuid4())
        
        # Generate verification token on creation
        if not self.verification_token:
            self.generate_verification_token()
        
        # Ensure plan fields are synchronized
        if 'plan' in kwargs and not self.subscription_plan:
            self.subscription_plan = kwargs['plan']
        elif 'subscription_plan' in kwargs and not self.plan:
            self.plan = kwargs['subscription_plan']
    
    # ========== PASSWORD MANAGEMENT ==========
    
    def set_password(self, password):
        """Hash and set password with history tracking"""
        # Check password strength
        if not self.is_password_strong(password):
            raise ValueError("Password does not meet security requirements")
        
        # Check against password history
        if self.is_password_in_history(password):
            raise ValueError("Password was used recently")
        
        # Store old hash in history
        if self.password_hash:
            self.add_to_password_history(self.password_hash)
        
        # Set new password
        self.password_hash = generate_password_hash(password)
        self.password_changed_at = datetime.utcnow()
        self.last_password_change = datetime.utcnow()
        
        # Reset security fields
        self.failed_login_attempts = 0
        self.lockout_until = None
        self.is_locked = False
    
    def check_password(self, password):
        """Verify password with timing attack protection"""
        return check_password_hash(self.password_hash, password)
    
    def is_password_strong(self, password):
        """Enhanced password strength validation"""
        if len(password) < 12:
            return False
        
        # Character type requirements
        checks = [
            any(c.isupper() for c in password),  # Uppercase
            any(c.islower() for c in password),  # Lowercase
            any(c.isdigit() for c in password),  # Digit
            any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?`~' for c in password)  # Special
        ]
        
        if not all(checks):
            return False
        
        # Common patterns check
        common_patterns = [
            'password', '123456', 'qwerty', 'admin', 'welcome',
            'letmein', 'monkey', 'dragon', 'sunshine', 'master'
        ]
        
        password_lower = password.lower()
        for pattern in common_patterns:
            if pattern in password_lower:
                return False
        
        # Sequential/repeating characters
        if re.search(r'(.)\1{3,}', password):
            return False
        
        # Keyboard patterns
        keyboard_patterns = [
            'qwerty', 'asdfgh', 'zxcvbn', 'qazwsx', '123qwe'
        ]
        for pattern in keyboard_patterns:
            if pattern in password_lower:
                return False
        
        return True
    
    def is_password_in_history(self, password, history_limit=5):
        """Check if password exists in history"""
        try:
            history = json.loads(self.password_history)
            for old_hash in history[-history_limit:]:
                if check_password_hash(old_hash, password):
                    return True
        except (json.JSONDecodeError, TypeError):
            pass
        return False
    
    def add_to_password_history(self, password_hash, max_history=10):
        """Add password hash to history"""
        try:
            history = json.loads(self.password_history)
        except (json.JSONDecodeError, TypeError):
            history = []
        
        history.append(password_hash)
        if len(history) > max_history:
            history = history[-max_history:]
        
        self.password_history = json.dumps(history)
    
    def is_password_expired(self, days=90):
        """Check if password needs to be changed"""
        if not self.password_changed_at:
            return False
        expiration_date = self.password_changed_at + timedelta(days=days)
        return datetime.utcnow() > expiration_date
    
    # ========== ACCOUNT LOCKOUT ==========
    
    def record_failed_login(self, ip_address=None):
        """Record failed login attempt and lock if needed"""
        self.failed_login_attempts += 1
        self.last_failed_login = datetime.utcnow()
        self.last_ip_address = ip_address
        
        # Lock account after 5 failed attempts
        if self.failed_login_attempts >= 5:
            self.lock_account(minutes=15)
        
        db.session.commit()
    
    def lock_account(self, minutes=15):
        """Lock user account for specified minutes"""
        self.is_locked = True
        self.lockout_until = datetime.utcnow() + timedelta(minutes=minutes)
    
    def unlock_account(self):
        """Unlock user account"""
        self.is_locked = False
        self.lockout_until = None
        self.failed_login_attempts = 0
    
    def is_account_locked(self):
        """Check if account is currently locked"""
        if not self.is_locked or not self.lockout_until:
            return False
        
        if datetime.utcnow() > self.lockout_until:
            self.unlock_account()
            return False
        
        return True
    
    def reset_login_attempts(self):
        """Reset failed login attempts"""
        self.failed_login_attempts = 0
        self.last_failed_login = None
    
    # ========== TOKEN MANAGEMENT ==========
    
    @staticmethod
    def generate_verification_token():
        """Generate secure verification token"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def generate_reset_token():
        """Generate secure password reset token"""
        return secrets.token_urlsafe(48)
    
    def generate_session_id(self):
        """Generate unique session ID"""
        self.current_session_id = hashlib.sha256(
            f"{self.id}{datetime.utcnow().timestamp()}{secrets.token_hex(16)}".encode()
        ).hexdigest()
        self.last_session_refresh = datetime.utcnow()
        return self.current_session_id
    
    def invalidate_all_sessions(self):
        """Invalidate all active sessions"""
        redis_client = get_redis_client()
        if redis_client:
            pattern = f"user:{self.id}:session:*"
            keys = redis_client.keys(pattern)
            for key in keys:
                redis_client.delete(key)
        
        self.current_session_id = None
        self.last_session_refresh = None
    
    # ========== ACCOUNT STATUS ==========
    
    def can_login(self):
        """Check if user is allowed to login"""
        if not self.is_active:
            return False, "Account is suspended"
        
        if self.is_deleted:
            return False, "Account is deleted"
        
        if self.is_suspended:
            return False, "Account is suspended by administrator"
        
        if self.is_account_locked():
            remaining = (self.lockout_until - datetime.utcnow()).seconds // 60
            return False, f"Account is locked. Try again in {remaining} minutes"
        
        if not self.email_verified:
            return False, "Email not verified"
        
        if self.is_password_expired():
            return False, "Password expired. Please reset your password"
        
        return True, "OK"
    
    def has_active_subscription(self):
        """Check if user has active subscription"""
        can_login, message = self.can_login()
        if not can_login:
            return False
        
        active_statuses = ['active', 'trialing']
        return self.subscription_status in active_statuses
    
    def can_access_feature(self, feature_name):
        """Check if user can access specific feature"""
        can_login, message = self.can_login()
        if not can_login:
            return False, message
        
        if not self.has_active_subscription() and self.subscription_plan == 'free':
            # Free tier limitations applied
            pass
        elif not self.has_active_subscription():
            return False, "No active subscription"
        
        plan_features = {
            'free': {
                'max_leads': 10,
                'max_properties': 5,
                'export': False,
                'api': False,
                'advanced_analytics': False
            },
            'basic': {
                'max_leads': 100,
                'max_properties': 50,
                'export': True,
                'api': False,
                'advanced_analytics': False
            },
            'pro': {
                'max_leads': 500,
                'max_properties': 200,
                'export': True,
                'api': True,
                'advanced_analytics': True
            },
            'enterprise': {
                'max_leads': -1,
                'max_properties': -1,
                'export': True,
                'api': True,
                'advanced_analytics': True
            }
        }
        
        plan = self.subscription_plan or 'free'
        
        if plan not in plan_features:
            return False, "Invalid subscription plan"
        
        return plan_features[plan].get(feature_name, False), "OK"
    
    # ========== ACCOUNT ACTIONS ==========
    
    def suspend(self, reason=None, admin_id=None):
        """Suspend user account"""
        self.is_active = False
        self.is_suspended = True
        self.suspended_at = datetime.utcnow()
        self.suspended_by = admin_id
        self.deletion_reason = reason
        self.invalidate_all_sessions()
        return self
    
    def restore(self):
        """Restore suspended user account"""
        self.is_active = True
        self.is_suspended = False
        self.suspended_at = None
        self.suspended_by = None
        self.deletion_reason = None
        return self
    
    def soft_delete(self, reason=None):
        """Soft delete user account"""
        self.is_deleted = True
        self.is_active = False
        self.deleted_at = datetime.utcnow()
        self.deletion_reason = reason
        self.invalidate_all_sessions()
        return self
    
    def verify_email(self):
        """Mark email as verified"""
        self.email_verified = True
        self.is_verified = True
        self.verified_at = datetime.utcnow()
        self.verification_token = None
        self.verification_token_expires = None
        return self
    
    def update_last_login(self, ip_address=None, user_agent=None):
        """Update last login information"""
        self.last_login_at = datetime.utcnow()
        self.login_count += 1
        self.last_ip_address = ip_address
        self.user_agent = user_agent
        self.reset_login_attempts()
        return self
    
    def downgrade_to_free(self):
        """Downgrade user to free tier"""
        self.subscription_plan = 'free'
        self.plan = 'free'
        self.subscription_status = 'inactive'
        self.update_plan_limits('free')
        self.subscription_id = None
        self.trial_ends_at = None
        return self
    
    def update_plan_limits(self, plan_name):
        """Update user limits based on plan"""
        plan_limits = {
            'free': {'max_leads': 10, 'max_properties': 5, 'export': False, 'api': False},
            'basic': {'max_leads': 100, 'max_properties': 50, 'export': True, 'api': False},
            'pro': {'max_leads': 500, 'max_properties': 200, 'export': True, 'api': True},
            'enterprise': {'max_leads': -1, 'max_properties': -1, 'export': True, 'api': True}
        }
        
        if plan_name in plan_limits:
            limits = plan_limits[plan_name]
            self.max_leads = limits['max_leads']
            self.max_properties = limits['max_properties']
            self.can_export_data = limits['export']
            self.has_api_access = limits['api']
            self.subscription_plan = plan_name
            self.plan = plan_name
        
        return self
    
    # ========== SERIALIZATION ==========
    
    def to_dict(self):
        """Convert user object to dictionary (exclude sensitive data)"""
        return {
            'id': self.id,
            'fullName': self.full_name,
            'email': self.email,
            'phone': self.phone,
            'company': self.company,
            'role': self.role,
            'stripeCustomerId': self.stripe_customer_id,
            'subscriptionStatus': self.subscription_status,
            'subscriptionPlan': self.subscription_plan,
            'plan': self.plan,
            'maxLeads': self.max_leads,
            'maxProperties': self.max_properties,
            'canExportData': self.can_export_data,
            'hasApiAccess': self.has_api_access,
            'isActive': self.is_active,
            'isSuspended': self.is_suspended,
            'isVerified': self.is_verified,
            'emailVerified': self.email_verified,
            'isDeleted': self.is_deleted,
            'mfaEnabled': self.mfa_enabled,
            'loginCount': self.login_count,
            'verifiedAt': self.verified_at.isoformat() if self.verified_at else None,
            'lastLoginAt': self.last_login_at.isoformat() if self.last_login_at else None,
            'trialEndsAt': self.trial_ends_at.isoformat() if self.trial_ends_at else None,
            'createdAt': self.created_at.isoformat() if self.created_at else None,
            'subscription': {
                'status': self.subscription_status,
                'plan': self.subscription_plan,
                'maxLeads': self.max_leads,
                'maxProperties': self.max_properties,
                'canExport': self.can_export_data,
                'hasApi': self.has_api_access
            }
        }
    
    def to_secure_dict(self):
        """Return user data with security status"""
        data = self.to_dict()
        data.update({
            'isLocked': self.is_locked,
            'lockoutUntil': self.lockout_until.isoformat() if self.lockout_until else None,
            'failedLoginAttempts': self.failed_login_attempts,
            'passwordExpired': self.is_password_expired(),
            'passwordChangedAt': self.password_changed_at.isoformat() if self.password_changed_at else None,
            'requiresPasswordChange': self.is_password_expired(30),  # Warn 30 days before expiry
            'lastIpAddress': self.last_ip_address
        })
        return data
    
    # ========== AUDIT LOGGING ==========
    
    def log_activity(self, action, details=None, ip_address=None):
        """Log user activity"""
        from app.models.audit_log import AuditLog
        
        log = AuditLog(
            user_id=self.id,
            action=action,
            details=details or {},
            ip_address=ip_address,
            user_agent=self.user_agent
        )
        db.session.add(log)
        return log
    
    # ========== HELPER METHODS ==========
    
    def __repr__(self):
        return f'<User {self.email} ({self.id})>'
    
    @property
    def is_authenticated(self):
        return self.is_active and not self.is_deleted
    
    @property
    def is_anonymous(self):
        return False