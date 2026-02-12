# plan_middleware.py
import time
import functools
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set, Callable, Any
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict

from flask import jsonify, request, current_app, g
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
import redis
import stripe
from prometheus_client import Counter, Histogram, Gauge
import sentry_sdk
from sentry_sdk import capture_exception

from app.models.user import User
from app.models.subscription import Subscription, SubscriptionHistory
from app.models.usage import FeatureUsage
from app.extensions import cache, db, redis_client
from app.utils.circuit_breaker import CircuitBreaker
from app.utils.rate_limiter import RateLimiter

# ===== CONSTANTS & CONFIGURATION =====

class PlanStatus(Enum):
    """Subscription status enumeration"""
    ACTIVE = "active"
    TRIALING = "trialing"
    CANCELED = "canceled"
    PAST_DUE = "past_due"
    UNPAID = "unpaid"
    INCOMPLETE = "incomplete"
    INCOMPLETE_EXPIRED = "incomplete_expired"
    
    @classmethod
    def is_active(cls, status: str) -> bool:
        """Check if status is considered active"""
        return status in [cls.ACTIVE.value, cls.TRIALING.value]
    
    @classmethod
    def is_expired_or_canceled(cls, status: str) -> bool:
        """Check if status indicates expired/canceled subscription"""
        return status in [
            cls.CANCELED.value, 
            cls.UNPAID.value, 
            cls.INCOMPLETE_EXPIRED.value
        ]


class FeatureAccess(Enum):
    """Feature access levels"""
    DENIED = 0
    GRANTED = 1
    LIMITED = 2  # Limited by usage quotas


@dataclass
class PlanLimits:
    """Plan-specific limits configuration"""
    plan_name: str
    max_api_calls: int
    max_exports: int
    max_users: int
    max_storage_gb: int
    retention_days: int
    rate_limit_rpm: int  # Requests per minute


# ===== METRICS & MONITORING =====

# Prometheus metrics for monitoring
PLAN_CHECK_COUNTER = Counter(
    'plan_middleware_checks_total',
    'Total plan access checks',
    ['plan', 'feature', 'result']
)

PLAN_CHECK_LATENCY = Histogram(
    'plan_middleware_check_duration_seconds',
    'Plan check latency in seconds',
    ['check_type']
)

ACTIVE_SUBSCRIPTIONS_GAUGE = Gauge(
    'active_subscriptions_total',
    'Number of active subscriptions by plan',
    ['plan']
)

FEATURE_USAGE_GAUGE = Gauge(
    'feature_usage_total',
    'Feature usage by plan',
    ['feature', 'plan']
)


# ===== CACHE CONFIGURATION =====

class CacheKeys:
    """Redis cache key patterns"""
    @staticmethod
    def user_plan(user_id: str) -> str:
        return f"user:{user_id}:plan"
    
    @staticmethod
    def user_status(user_id: str) -> str:
        return f"user:{user_id}:status"
    
    @staticmethod
    def user_limits(user_id: str) -> str:
        return f"user:{user_id}:limits"
    
    @staticmethod
    def usage_tracking(user_id: str, feature: str) -> str:
        return f"user:{user_id}:usage:{feature}"
    
    @staticmethod
    def stripe_sync(user_id: str) -> str:
        return f"stripe:sync:{user_id}"
    
    @staticmethod
    def plan_limits(plan_name: str) -> str:
        return f"plan:limits:{plan_name}"


# ===== ADVANCED PLAN MIDDLEWARE =====

class AdvancedPlanMiddleware:
    """Enterprise-grade subscription and feature access management"""
    
    # Enhanced plan hierarchy with trial support
    PLAN_LEVELS = {
        'free': {'level': 0, 'has_trial': False},
        'trial': {'level': 1, 'has_trial': True, 'trial_days': 14},
        'basic': {'level': 2, 'has_trial': True, 'trial_days': 7},
        'pro': {'level': 3, 'has_trial': True, 'trial_days': 7},
        'enterprise': {'level': 4, 'has_trial': False}
    }
    
    # Feature access with granular permissions
    FEATURE_MATRIX = {
        'export': {
            'min_plan': 'basic',
            'rate_limit': 100,  # per hour
            'concurrent_limit': 5,
            'requires_2fa': False
        },
        'api': {
            'min_plan': 'pro',
            'rate_limit': 1000,  # per hour
            'concurrent_limit': 20,
            'requires_2fa': True
        },
        'advanced_analytics': {
            'min_plan': 'pro',
            'rate_limit': 500,
            'concurrent_limit': 10,
            'requires_2fa': False
        },
        'unlimited_leads': {
            'min_plan': 'enterprise',
            'rate_limit': None,  # Unlimited
            'concurrent_limit': 50,
            'requires_2fa': True
        },
        'multi_user': {
            'min_plan': 'enterprise',
            'rate_limit': None,
            'concurrent_limit': 100,
            'requires_2fa': True
        },
        'white_label': {
            'min_plan': 'enterprise',
            'rate_limit': None,
            'concurrent_limit': 10,
            'requires_2fa': True
        }
    }
    
    # Plan-specific limits configuration
    PLAN_LIMITS_CONFIG = {
        'free': PlanLimits(
            plan_name='free',
            max_api_calls=100,
            max_exports=10,
            max_users=1,
            max_storage_gb=1,
            retention_days=30,
            rate_limit_rpm=60
        ),
        'basic': PlanLimits(
            plan_name='basic',
            max_api_calls=1000,
            max_exports=100,
            max_users=3,
            max_storage_gb=10,
            retention_days=90,
            rate_limit_rpm=300
        ),
        'pro': PlanLimits(
            plan_name='pro',
            max_api_calls=10000,
            max_exports=1000,
            max_users=10,
            max_storage_gb=100,
            retention_days=365,
            rate_limit_rpm=1000
        ),
        'enterprise': PlanLimits(
            plan_name='enterprise',
            max_api_calls=1000000,
            max_exports=100000,
            max_users=1000,
            max_storage_gb=1000,
            retention_days=730,
            rate_limit_rpm=5000
        )
    }
    
    # Grace periods for failed payments
    GRACE_PERIOD_DAYS = {
        'basic': 3,
        'pro': 7,
        'enterprise': 14
    }
    
    # Circuit breaker for external service calls
    _stripe_circuit_breaker = CircuitBreaker(
        failure_threshold=5,
        recovery_timeout=60,
        expected_exceptions=(stripe.error.StripeError,)
    )
    
    # Rate limiter for plan checks
    _rate_limiter = RateLimiter(requests_per_minute=1000)
    
    # Cache for plan validation results (short-lived)
    _validation_cache = {}
    _cache_lock = threading.Lock()
    
    @classmethod
    def get_current_user(cls, force_refresh: bool = False) -> Optional[User]:
        """
        Get current authenticated user with caching
        
        Args:
            force_refresh: Bypass cache and fetch fresh from DB
            
        Returns:
            User object or None
        """
        start_time = time.time()
        
        try:
            user_id = get_jwt_identity()
            if not user_id:
                return None
            
            cache_key = CacheKeys.user_plan(user_id)
            
            # Return cached user if available and not forcing refresh
            if not force_refresh:
                cached = redis_client.get(cache_key)
                if cached:
                    user_data = pickle.loads(cached)
                    if user_data.get('cached_at', 0) > time.time() - 300:  # 5 min cache
                        PLAN_CHECK_LATENCY.labels('cache_hit').observe(time.time() - start_time)
                        return User(**user_data['user_data'])
            
            # Fetch from database
            with db.session.begin():
                user = User.query.get(user_id)
                if not user:
                    return None
                
                # Verify JWT matches user
                verify_jwt_in_request()
                
                # Cache user data
                user_data = {
                    'user_data': user.to_dict(),
                    'cached_at': time.time()
                }
                redis_client.setex(
                    cache_key,
                    300,  # 5 minutes TTL
                    pickle.dumps(user_data)
                )
                
                PLAN_CHECK_LATENCY.labels('db_fetch').observe(time.time() - start_time)
                return user
                
        except Exception as e:
            capture_exception(e)
            current_app.logger.error(f"Failed to get current user: {e}")
            PLAN_CHECK_COUNTER.labels(plan='unknown', feature='auth', result='error').inc()
            return None
    
    @classmethod
    def validate_subscription_status(cls, user: User) -> Dict[str, Any]:
        """
        Comprehensive subscription validation with Stripe sync
        
        Args:
            user: User object to validate
            
        Returns:
            Dict with validation results
        """
        validation_start = time.time()
        
        try:
            # Check cache first
            cache_key = CacheKeys.user_status(user.id)
            cached_status = redis_client.get(cache_key)
            if cached_status:
                status_data = pickle.loads(cached_status)
                if status_data.get('valid_until', 0) > time.time():
                    return status_data
            
            # Get subscription from database
            subscription = Subscription.query.filter_by(
                user_id=user.id,
                is_active=True
            ).first()
            
            if not subscription:
                return {
                    'is_valid': False,
                    'reason': 'no_subscription',
                    'grace_period': False,
                    'valid_until': time.time() + 60  # Cache for 1 minute
                }
            
            # Check for Stripe sync delays
            sync_key = CacheKeys.stripe_sync(user.id)
            last_sync = redis_client.get(sync_key)
            
            # Force Stripe sync if more than 5 minutes old
            if not last_sync or float(last_sync) < time.time() - 300:
                cls._sync_with_stripe(subscription)
                redis_client.setex(sync_key, 300, str(time.time()))
            
            # Enhanced status validation
            current_time = datetime.utcnow()
            
            # Check if subscription is expired
            if subscription.end_date and subscription.end_date < current_time:
                # Apply grace period based on plan
                grace_days = cls.GRACE_PERIOD_DAYS.get(user.subscription_plan, 0)
                grace_until = subscription.end_date + timedelta(days=grace_days)
                
                if grace_until > current_time:
                    status = {
                        'is_valid': True,
                        'reason': 'grace_period',
                        'grace_period': True,
                        'grace_until': grace_until.isoformat(),
                        'valid_until': time.time() + 180  # Shorter cache for grace
                    }
                else:
                    status = {
                        'is_valid': False,
                        'reason': 'subscription_expired',
                        'grace_period': False,
                        'valid_until': time.time() + 300
                    }
            # Check subscription status
            elif PlanStatus.is_expired_or_canceled(subscription.status):
                status = {
                    'is_valid': False,
                    'reason': f'subscription_{subscription.status}',
                    'grace_period': False,
                    'valid_until': time.time() + 300
                }
            elif not PlanStatus.is_active(subscription.status):
                status = {
                    'is_valid': False,
                    'reason': f'subscription_{subscription.status}',
                    'grace_period': False,
                    'valid_until': time.time() + 300
                }
            else:
                # Valid subscription
                status = {
                    'is_valid': True,
                    'reason': 'active_subscription',
                    'grace_period': False,
                    'valid_until': time.time() + 300
                }
            
            # Update metrics
            ACTIVE_SUBSCRIPTIONS_GAUGE.labels(plan=user.subscription_plan).set(
                1 if status['is_valid'] else 0
            )
            
            # Cache validation result
            redis_client.setex(cache_key, 300, pickle.dumps(status))
            
            PLAN_CHECK_LATENCY.labels('validation').observe(time.time() - validation_start)
            
            return status
            
        except Exception as e:
            capture_exception(e)
            current_app.logger.error(f"Subscription validation failed: {e}")
            
            # Fallback: allow access if we can't validate (fail-open for availability)
            # But mark as suspicious for monitoring
            sentry_sdk.capture_message(f"Subscription validation failed for user {user.id}")
            
            return {
                'is_valid': True,  # Fail-open for availability
                'reason': 'validation_failed',
                'grace_period': False,
                'valid_until': time.time() + 60,  # Very short cache
                'needs_revalidation': True
            }
    
    @classmethod
    @_stripe_circuit_breaker
    def _sync_with_stripe(cls, subscription: Subscription) -> None:
        """
        Sync subscription status with Stripe with circuit breaker
        
        Args:
            subscription: Subscription to sync
        """
        try:
            # Fetch latest from Stripe
            stripe_sub = stripe.Subscription.retrieve(subscription.stripe_subscription_id)
            
            # Update local database
            subscription.status = stripe_sub.status
            subscription.current_period_end = datetime.fromtimestamp(
                stripe_sub.current_period_end
            )
            subscription.cancel_at_period_end = stripe_sub.cancel_at_period_end
            
            # Update plan if changed
            if stripe_sub.items.data:
                stripe_plan = stripe_sub.items.data[0].plan
                if stripe_plan and stripe_plan.id != subscription.plan_id:
                    subscription.plan_id = stripe_plan.id
                    # Log plan change
                    SubscriptionHistory.log_change(
                        subscription.user_id,
                        old_plan=subscription.plan_id,
                        new_plan=stripe_plan.id,
                        reason='stripe_sync'
                    )
            
            db.session.commit()
            
        except stripe.error.StripeError as e:
            current_app.logger.warning(f"Stripe sync failed: {e}")
            # Don't raise - allow local data to be used
            raise  # Let circuit breaker handle this
        except Exception as e:
            capture_exception(e)
            current_app.logger.error(f"Unexpected error during Stripe sync: {e}")
            db.session.rollback()
    
    @classmethod
    def check_feature_access(cls, user: User, feature: str, 
                           increment_usage: bool = False) -> Tuple[bool, Dict[str, Any]]:
        """
        Comprehensive feature access check with usage tracking
        
        Args:
            user: User object
            feature: Feature name
            increment_usage: Whether to increment usage counter
            
        Returns:
            Tuple of (access_granted, metadata)
        """
        check_start = time.time()
        
        try:
            # Rate limit feature checks
            if not cls._rate_limiter.allow_request(f"feature_check:{user.id}:{feature}"):
                PLAN_CHECK_COUNTER.labels(
                    plan=user.subscription_plan, 
                    feature=feature, 
                    result='rate_limited'
                ).inc()
                return False, {'reason': 'rate_limited', 'retry_after': 60}
            
            # Get feature config
            feature_config = cls.FEATURE_MATRIX.get(feature)
            if not feature_config:
                PLAN_CHECK_COUNTER.labels(
                    plan=user.subscription_plan, 
                    feature=feature, 
                    result='feature_not_found'
                ).inc()
                return False, {'reason': 'feature_not_found'}
            
            # Check minimum plan requirement
            if not cls.plan_has_access(user.subscription_plan, feature_config['min_plan']):
                PLAN_CHECK_COUNTER.labels(
                    plan=user.subscription_plan, 
                    feature=feature, 
                    result='insufficient_plan'
                ).inc()
                return False, {
                    'reason': 'insufficient_plan',
                    'required_plan': feature_config['min_plan'],
                    'current_plan': user.subscription_plan
                }
            
            # Check 2FA requirement
            if feature_config.get('requires_2fa') and not user.two_factor_enabled:
                return False, {
                    'reason': '2fa_required',
                    'feature': feature
                }
            
            # Check subscription status
            sub_status = cls.validate_subscription_status(user)
            if not sub_status['is_valid']:
                PLAN_CHECK_COUNTER.labels(
                    plan=user.subscription_plan, 
                    feature=feature, 
                    result='invalid_subscription'
                ).inc()
                return False, {
                    'reason': 'invalid_subscription',
                    'subscription_reason': sub_status['reason']
                }
            
            # Check concurrent usage limit
            if feature_config.get('concurrent_limit'):
                current_usage = cls._get_concurrent_usage(user.id, feature)
                if current_usage >= feature_config['concurrent_limit']:
                    return False, {
                        'reason': 'concurrent_limit_exceeded',
                        'current': current_usage,
                        'limit': feature_config['concurrent_limit']
                    }
            
            # Check rate limit
            if feature_config.get('rate_limit'):
                usage_key = f"rate_limit:{user.id}:{feature}:{int(time.time() // 3600)}"
                current_count = redis_client.incr(usage_key)
                redis_client.expire(usage_key, 3600)  # 1 hour TTL
                
                if current_count > feature_config['rate_limit']:
                    PLAN_CHECK_COUNTER.labels(
                        plan=user.subscription_plan, 
                        feature=feature, 
                        result='rate_limit_exceeded'
                    ).inc()
                    return False, {
                        'reason': 'rate_limit_exceeded',
                        'current': current_count,
                        'limit': feature_config['rate_limit'],
                        'reset_in': 3600 - (time.time() % 3600)
                    }
            
            # Check plan-specific usage limits
            plan_limits = cls.get_plan_limits(user.subscription_plan)
            if plan_limits:
                # Map feature to limit field
                limit_mapping = {
                    'api': 'max_api_calls',
                    'export': 'max_exports'
                }
                
                limit_field = limit_mapping.get(feature)
                if limit_field:
                    current_usage = FeatureUsage.get_current_usage(
                        user.id, 
                        feature, 
                        period='monthly'
                    )
                    max_limit = getattr(plan_limits, limit_field)
                    
                    if current_usage >= max_limit:
                        PLAN_CHECK_COUNTER.labels(
                            plan=user.subscription_plan, 
                            feature=feature, 
                            result='usage_limit_exceeded'
                        ).inc()
                        return False, {
                            'reason': 'usage_limit_exceeded',
                            'current': current_usage,
                            'limit': max_limit,
                            'reset_date': FeatureUsage.get_reset_date(user.id, feature)
                        }
            
            # Increment usage if requested
            if increment_usage:
                FeatureUsage.record_usage(user.id, feature)
                FEATURE_USAGE_GAUGE.labels(feature=feature, plan=user.subscription_plan).inc()
            
            PLAN_CHECK_COUNTER.labels(
                plan=user.subscription_plan, 
                feature=feature, 
                result='granted'
            ).inc()
            
            PLAN_CHECK_LATENCY.labels('feature_check').observe(time.time() - check_start)
            
            return True, {
                'reason': 'access_granted',
                'plan': user.subscription_plan,
                'feature': feature,
                'limits': cls._get_remaining_limits(user, feature)
            }
            
        except Exception as e:
            capture_exception(e)
            current_app.logger.error(f"Feature access check failed: {e}")
            
            # Fail-closed for security-critical features, fail-open for others
            security_critical = feature_config.get('requires_2fa', False)
            if security_critical:
                return False, {'reason': 'check_failed', 'error': str(e)}
            else:
                # Allow access but log the failure
                return True, {
                    'reason': 'check_failed_allow',
                    'error': str(e),
                    'needs_revalidation': True
                }
    
    @classmethod
    def _get_concurrent_usage(cls, user_id: str, feature: str) -> int:
        """Get current concurrent usage for a feature"""
        key = f"concurrent:{user_id}:{feature}"
        return int(redis_client.get(key) or 0)
    
    @classmethod
    def _get_remaining_limits(cls, user: User, feature: str) -> Dict[str, Any]:
        """Get remaining usage limits for a feature"""
        plan_limits = cls.get_plan_limits(user.subscription_plan)
        if not plan_limits:
            return {}
        
        # Calculate remaining based on feature type
        if feature in ['api', 'export']:
            current = FeatureUsage.get_current_usage(user.id, feature, period='monthly')
            limit_field = 'max_api_calls' if feature == 'api' else 'max_exports'
            limit = getattr(plan_limits, limit_field)
            
            return {
                'remaining': max(0, limit - current),
                'used': current,
                'limit': limit,
                'percentage': (current / limit * 100) if limit > 0 else 0
            }
        
        return {}
    
    @classmethod
    def plan_has_access(cls, user_plan: str, required_plan: str) -> bool:
        """Check if user's plan meets or exceeds required plan"""
        user_level = cls.PLAN_LEVELS.get(user_plan, {}).get('level', 0)
        required_level = cls.PLAN_LEVELS.get(required_plan, {}).get('level', 0)
        return user_level >= required_level
    
    @classmethod
    def get_plan_limits(cls, plan_name: str) -> Optional[PlanLimits]:
        """Get limits for a specific plan"""
        return cls.PLAN_LIMITS_CONFIG.get(plan_name)


# ===== ADVANCED DECORATORS =====

def require_plan(plan_name: str, allow_trial: bool = True, 
                 grace_period: bool = False) -> Callable:
    """
    Advanced decorator to require minimum subscription plan
    
    Args:
        plan_name: Minimum required plan
        allow_trial: Whether to allow trial users
        grace_period: Whether to allow grace period access
        
    Usage:
        @require_plan("pro", allow_trial=True)
        def premium_endpoint():
            ...
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Rate limit plan checks
            user_id = get_jwt_identity()
            if user_id:
                rate_key = f"plan_check_rate:{user_id}:{plan_name}"
                if not AdvancedPlanMiddleware._rate_limiter.allow_request(rate_key):
                    return jsonify({
                        "error": "Too many requests",
                        "message": "Please slow down your plan checks",
                        "retry_after": 60
                    }), 429
            
            # Get user with cache bypass for security checks
            user = AdvancedPlanMiddleware.get_current_user(force_refresh=True)
            if not user:
                return jsonify({
                    "error": "Authentication required",
                    "code": "auth_required"
                }), 401
            
            # Check plan access
            if not AdvancedPlanMiddleware.plan_has_access(user.subscription_plan, plan_name):
                # Check if user is on trial
                if allow_trial and user.subscription_plan == 'trial':
                    # Check trial expiration
                    if user.trial_expires_at and user.trial_expires_at < datetime.utcnow():
                        return jsonify({
                            "error": "Trial expired",
                            "message": "Your trial period has ended",
                            "trial_expired": True,
                            "plans_url": "/pricing"
                        }), 403
                else:
                    return jsonify({
                        "error": "Insufficient plan",
                        "message": f"'{plan_name}' plan or higher required",
                        "required_plan": plan_name,
                        "current_plan": user.subscription_plan,
                        "upgrade_url": f"/billing/upgrade?plan={plan_name}",
                        "compare_url": "/pricing/compare"
                    }), 403
            
            # Validate subscription status
            sub_status = AdvancedPlanMiddleware.validate_subscription_status(user)
            if not sub_status['is_valid']:
                # Check if we allow grace period
                if grace_period and sub_status.get('grace_period'):
                    # Add grace period warning header
                    g.grace_period = True
                    g.grace_until = sub_status.get('grace_until')
                else:
                    return jsonify({
                        "error": "Subscription issue",
                        "message": "Your subscription needs attention",
                        "reason": sub_status['reason'],
                        "resolve_url": "/billing/resolve"
                    }), 403
            
            # Add plan info to request context
            g.user_plan = user.subscription_plan
            g.plan_level = AdvancedPlanMiddleware.PLAN_LEVELS.get(user.subscription_plan, {}).get('level', 0)
            g.subscription_status = sub_status
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_feature(feature_name: str, track_usage: bool = True,
                    require_2fa: Optional[bool] = None) -> Callable:
    """
    Advanced feature access decorator with usage tracking
    
    Args:
        feature_name: Feature to check
        track_usage: Whether to track usage
        require_2fa: Override 2FA requirement
        
    Usage:
        @require_feature("api", track_usage=True)
        def api_endpoint():
            ...
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            user = AdvancedPlanMiddleware.get_current_user()
            if not user:
                return jsonify({"error": "Authentication required"}), 401
            
            # Get feature config
            feature_config = AdvancedPlanMiddleware.FEATURE_MATRIX.get(feature_name)
            if not feature_config:
                return jsonify({"error": "Feature not found"}), 404
            
            # Check 2FA if required
            if require_2fa or feature_config.get('requires_2fa', False):
                if not user.two_factor_enabled:
                    return jsonify({
                        "error": "Two-factor authentication required",
                        "message": "This feature requires 2FA to be enabled",
                        "setup_url": "/security/2fa/setup"
                    }), 403
            
            # Check feature access
            access_granted, metadata = AdvancedPlanMiddleware.check_feature_access(
                user, feature_name, increment_usage=track_usage
            )
            
            if not access_granted:
                error_response = {
                    "error": "Feature access denied",
                    "reason": metadata.get('reason', 'unknown'),
                    "feature": feature_name
                }
                
                # Add contextual information
                if metadata.get('required_plan'):
                    error_response.update({
                        "required_plan": metadata['required_plan'],
                        "current_plan": metadata.get('current_plan'),
                        "upgrade_url": f"/billing/upgrade?feature={feature_name}"
                    })
                
                if metadata.get('retry_after'):
                    error_response['retry_after'] = metadata['retry_after']
                
                if metadata.get('reset_in'):
                    error_response['reset_in'] = metadata['reset_in']
                
                return jsonify(error_response), 403
            
            # Add feature metadata to context
            g.feature_access = {
                'feature': feature_name,
                'limits': metadata.get('limits', {}),
                'requires_2fa': feature_config.get('requires_2fa', False)
            }
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_active_subscription(allow_trial: bool = True, 
                                allow_grace_period: bool = False) -> Callable:
    """
    Decorator to require active subscription with flexible options
    
    Args:
        allow_trial: Allow trial users
        allow_grace_period: Allow grace period for payment issues
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            user = AdvancedPlanMiddleware.get_current_user()
            if not user:
                return jsonify({"error": "Authentication required"}), 401
            
            # Validate subscription
            sub_status = AdvancedPlanMiddleware.validate_subscription_status(user)
            
            if not sub_status['is_valid']:
                # Check exceptions
                if allow_trial and user.subscription_plan == 'trial':
                    trial_valid = user.trial_expires_at and user.trial_expires_at > datetime.utcnow()
                    if not trial_valid:
                        return jsonify({
                            "error": "Trial expired",
                            "message": "Please upgrade to continue",
                            "upgrade_url": "/pricing"
                        }), 403
                elif allow_grace_period and sub_status.get('grace_period'):
                    # Allow but warn
                    g.grace_period = True
                    g.grace_until = sub_status.get('grace_until')
                else:
                    return jsonify({
                        "error": "Subscription required",
                        "message": "Please subscribe to access this content",
                        "reason": sub_status.get('reason', 'unknown'),
                        "plans_url": "/pricing"
                    }), 403
            
            # Add subscription info to context
            g.subscription = {
                'plan': user.subscription_plan,
                'status': sub_status,
                'is_trial': user.subscription_plan == 'trial',
                'trial_expires': user.trial_expires_at.isoformat() if user.trial_expires_at else None
            }
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def track_usage_with_limits(feature_name: str, cost: int = 1, 
                           soft_limit_ratio: float = 0.9) -> Callable:
    """
    Advanced usage tracking with soft/hard limits
    
    Args:
        feature_name: Feature to track
        cost: Usage cost in units
        soft_limit_ratio: Ratio at which to warn (0.9 = 90% usage)
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            user = AdvancedPlanMiddleware.get_current_user()
            
            if user:
                try:
                    # Get current usage
                    current_usage = FeatureUsage.get_current_usage(
                        user.id, feature_name, period='monthly'
                    )
                    
                    # Get plan limits
                    plan_limits = AdvancedPlanMiddleware.get_plan_limits(user.subscription_plan)
                    if plan_limits:
                        # Map feature to limit
                        limit_mapping = {
                            'api': 'max_api_calls',
                            'export': 'max_exports'
                        }
                        
                        limit_field = limit_mapping.get(feature_name)
                        if limit_field:
                            max_limit = getattr(plan_limits, limit_field)
                            
                            # Check hard limit
                            if current_usage + cost > max_limit:
                                return jsonify({
                                    "error": "Usage limit exceeded",
                                    "message": f"You've reached your {feature_name} limit",
                                    "feature": feature_name,
                                    "used": current_usage,
                                    "limit": max_limit,
                                    "reset_date": FeatureUsage.get_reset_date(user.id, feature_name),
                                    "upgrade_url": f"/billing/upgrade?reason=limit_{feature_name}"
                                }), 429
                            
                            # Check soft limit (warn but allow)
                            if current_usage + cost > max_limit * soft_limit_ratio:
                                g.usage_warning = {
                                    "feature": feature_name,
                                    "current_usage": current_usage,
                                    "limit": max_limit,
                                    "percentage": (current_usage / max_limit * 100),
                                    "warning": "Approaching usage limit"
                                }
                    
                    # Record usage
                    FeatureUsage.record_usage(user.id, feature_name, cost)
                    FEATURE_USAGE_GAUGE.labels(
                        feature=feature_name, 
                        plan=user.subscription_plan
                    ).inc(cost)
                    
                except Exception as e:
                    capture_exception(e)
                    current_app.logger.error(f"Usage tracking failed: {e}")
                    # Continue execution even if tracking fails
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ===== HELPER FUNCTIONS & UTILITIES =====

def get_user_plan_info(user_id: str = None, include_usage: bool = True) -> Dict[str, Any]:
    """
    Get comprehensive plan information for a user
    
    Args:
        user_id: User ID (defaults to current user)
        include_usage: Include current usage statistics
        
    Returns:
        Comprehensive plan information
    """
    if not user_id:
        user_id = get_jwt_identity()
    
    user = User.query.get(user_id) if user_id else None
    if not user:
        return None
    
    # Get subscription status
    sub_status = AdvancedPlanMiddleware.validate_subscription_status(user)
    
    # Get plan limits
    plan_limits = AdvancedPlanMiddleware.get_plan_limits(user.subscription_plan)
    
    # Compile features access
    features = {}
    for feature_name, config in AdvancedPlanMiddleware.FEATURE_MATRIX.items():
        has_access, _ = AdvancedPlanMiddleware.check_feature_access(user, feature_name)
        
        features[feature_name] = {
            'has_access': has_access,
            'requires_plan': config['min_plan'],
            'requires_2fa': config.get('requires_2fa', False),
            'rate_limit': config.get('rate_limit'),
            'concurrent_limit': config.get('concurrent_limit')
        }
        
        # Add usage info if requested
        if include_usage and has_access:
            if feature_name in ['api', 'export']:
                current_usage = FeatureUsage.get_current_usage(user.id, feature_name, 'monthly')
                limit_field = 'max_api_calls' if feature_name == 'api' else 'max_exports'
                
                features[feature_name]['usage'] = {
                    'current': current_usage,
                    'limit': getattr(plan_limits, limit_field) if plan_limits else None,
                    'reset_date': FeatureUsage.get_reset_date(user.id, feature_name)
                }
    
    return {
        "user_id": user.id,
        "plan": user.subscription_plan,
        "plan_level": AdvancedPlanMiddleware.PLAN_LEVELS.get(user.subscription_plan, {}).get('level', 0),
        "subscription_status": {
            "is_valid": sub_status['is_valid'],
            "reason": sub_status['reason'],
            "grace_period": sub_status.get('grace_period', False),
            "grace_until": sub_status.get('grace_until')
        },
        "is_trial": user.subscription_plan == 'trial',
        "trial_expires": user.trial_expires_at.isoformat() if user.trial_expires_at else None,
        "plan_limits": plan_limits.__dict__ if plan_limits else None,
        "features": features,
        "upgrade_options": _get_upgrade_options(user.subscription_plan),
        "next_billing_date": _get_next_billing_date(user.id),
        "can_cancel": _can_cancel_subscription(user.id),
        "metadata": {
            "last_updated": datetime.utcnow().isoformat(),
            "cache_ttl": 60
        }
    }


def check_access_with_context(user_plan: str, required_plan_or_feature: str, 
                             user_id: str = None) -> Dict[str, Any]:
    """
    Advanced access checking with full context
    
    Args:
        user_plan: User's subscription plan
        required_plan_or_feature: Plan or feature to check
        user_id: Optional user ID for usage checking
        
    Returns:
        Detailed access information
    """
    # Check if it's a feature or plan
    if required_plan_or_feature in AdvancedPlanMiddleware.FEATURE_MATRIX:
        has_access, metadata = AdvancedPlanMiddleware.check_feature_access(
            user_plan, required_plan_or_feature
        )
        
        result = {
            "type": "feature",
            "feature": required_plan_or_feature,
            "has_access": has_access,
            "metadata": metadata
        }
        
        # Add usage info if user_id provided
        if user_id and has_access:
            current_usage = FeatureUsage.get_current_usage(
                user_id, required_plan_or_feature, 'monthly'
            )
            result['usage'] = {
                'current': current_usage,
                'reset_date': FeatureUsage.get_reset_date(user_id, required_plan_or_feature)
            }
    else:
        has_access = AdvancedPlanMiddleware.plan_has_access(user_plan, required_plan_or_feature)
        
        result = {
            "type": "plan",
            "required_plan": required_plan_or_feature,
            "has_access": has_access,
            "user_plan": user_plan,
            "user_level": AdvancedPlanMiddleware.PLAN_LEVELS.get(user_plan, {}).get('level', 0),
            "required_level": AdvancedPlanMiddleware.PLAN_LEVELS.get(required_plan_or_feature, {}).get('level', 0)
        }
    
    return result


def enforce_rate_limits(plan_name: str, endpoint: str) -> bool:
    """
    Enforce rate limits based on plan
    
    Args:
        plan_name: User's plan
        endpoint: API endpoint being accessed
        
    Returns:
        True if request should be allowed
    """
    user_id = get_jwt_identity()
    if not user_id:
        return True  # Public endpoints handled elsewhere
    
    # Get rate limits for plan
    plan_limits = AdvancedPlanMiddleware.get_plan_limits(plan_name)
    if not plan_limits:
        return True
    
    # Create rate limit key
    minute = int(time.time() // 60)
    key = f"rate_limit:{user_id}:{endpoint}:{minute}"
    
    # Increment counter
    current = redis_client.incr(key)
    redis_client.expire(key, 60)  # 1 minute TTL
    
    # Check against limit
    if current > plan_limits.rate_limit_rpm:
        return False
    
    return True


def _get_upgrade_options(current_plan: str) -> List[Dict[str, Any]]:
    """Get available upgrade options for current plan"""
    current_level = AdvancedPlanMiddleware.PLAN_LEVELS.get(current_plan, {}).get('level', 0)
    
    upgrades = []
    for plan_name, plan_info in AdvancedPlanMiddleware.PLAN_LEVELS.items():
        if plan_info['level'] > current_level:
            plan_limits = AdvancedPlanMiddleware.get_plan_limits(plan_name)
            
            upgrades.append({
                'plan': plan_name,
                'level': plan_info['level'],
                'features': [
                    feature for feature, config in AdvancedPlanMiddleware.FEATURE_MATRIX.items()
                    if config['min_plan'] == plan_name
                ],
                'limits': plan_limits.__dict__ if plan_limits else None,
                'price': _get_plan_price(plan_name),
                'upgrade_url': f"/billing/upgrade?plan={plan_name}"
            })
    
    return upgrades


def _get_plan_price(plan_name: str) -> Optional[Dict[str, Any]]:
    """Get pricing information for a plan"""
    # This would typically come from Stripe or a pricing database
    prices = {
        'basic': {'monthly': 29, 'yearly': 290, 'currency': 'USD'},
        'pro': {'monthly': 99, 'yearly': 990, 'currency': 'USD'},
        'enterprise': {'monthly': 499, 'yearly': 4990, 'currency': 'USD'}
    }
    return prices.get(plan_name)


def _get_next_billing_date(user_id: str) -> Optional[str]:
    """Get next billing date for user"""
    subscription = Subscription.query.filter_by(
        user_id=user_id, 
        is_active=True
    ).first()
    
    if subscription and subscription.current_period_end:
        return subscription.current_period_end.isoformat()
    
    return None


def _can_cancel_subscription(user_id: str) -> bool:
    """Check if user can cancel subscription"""
    subscription = Subscription.query.filter_by(
        user_id=user_id, 
        is_active=True
    ).first()
    
    if not subscription:
        return False
    
    # Can cancel unless in trial (trials auto-cancel at end)
    return subscription.plan_id != 'trial'


# ===== MIDDLEWARE CLASS FOR FLASK CONTEXT =====

class PlanMiddlewareExtension:
    """Flask extension for plan middleware"""
    
    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the extension"""
        app.extensions['plan_middleware'] = self
        
        # Register context processors
        @app.context_processor
        def inject_plan_info():
            """Inject plan information into templates"""
            user_id = get_jwt_identity()
            if not user_id:
                return {}
            
            user = AdvancedPlanMiddleware.get_current_user()
            if not user:
                return {}
            
            return {
                'user_plan': user.subscription_plan,
                'plan_level': AdvancedPlanMiddleware.PLAN_LEVELS.get(user.subscription_plan, {}).get('level', 0),
                'is_trial': user.subscription_plan == 'trial',
                'trial_expires': user.trial_expires_at
            }
        
        # Register error handlers
        @app.errorhandler(429)
        def handle_rate_limit(e):
            return jsonify({
                "error": "Rate limit exceeded",
                "message": "You've made too many requests. Please slow down.",
                "retry_after": 60
            }), 429
        
        @app.errorhandler(403)
        def handle_forbidden(e):
            # Check if it's a plan-related 403
            original_response = e.get_response()
            if 'Insufficient plan' in original_response.get_data(as_text=True):
                return jsonify({
                    "error": "Plan upgrade required",
                    "message": "This feature requires a higher subscription plan",
                    "action": "upgrade",
                    "url": "/pricing"
                }), 403
            return e


# ===== ADMIN FUNCTIONS =====

def admin_override(user_id: str, plan: str = None, 
                  feature: str = None, override_type: str = 'temp') -> Dict[str, Any]:
    """
    Admin function to override plan/feature access
    
    WARNING: Use with extreme caution. Should be protected by admin-only permissions.
    
    Args:
        user_id: User ID to override
        plan: Plan to override to (optional)
        feature: Feature to grant access to (optional)
        override_type: 'temp' (24h) or 'perm' (permanent)
        
    Returns:
        Override details
    """
    ttl = 86400 if override_type == 'temp' else None  # 24 hours or permanent
    
    overrides = {}
    
    if plan:
        key = f"admin_override:plan:{user_id}"
        redis_client.setex(key, ttl, plan) if ttl else redis_client.set(key, plan)
        overrides['plan'] = plan
    
    if feature:
        key = f"admin_override:feature:{user_id}:{feature}"
        redis_client.setex(key, ttl, 'granted') if ttl else redis_client.set(key, 'granted')
        overrides['features'] = [feature]
    
    # Log the override
    current_app.logger.warning(
        f"Admin override applied: user={user_id}, "
        f"overrides={overrides}, type={override_type}"
    )
    
    return {
        "user_id": user_id,
        "overrides": overrides,
        "type": override_type,
        "expires": time.time() + ttl if ttl else None,
        "applied_at": datetime.utcnow().isoformat()
    }


# Initialize the extension
plan_middleware = PlanMiddlewareExtension()