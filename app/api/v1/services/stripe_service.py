# stripe_service.py - ADVANCED FEATURE FLAG INTEGRATION
import stripe
import os
import uuid
import json
import logging
from datetime import datetime
from typing import Optional, Dict, List, Any, Tuple, Union, Callable
from functools import wraps
from contextlib import contextmanager
from flask import current_app
from app.config import settings
from app.extensions import db
from app.models.stripe import SubscriptionState

# Advanced imports
from config.feature_flags import feature_flags
from dataclasses import dataclass, asdict
from enum import Enum
from threading import Lock
import sentry_sdk
from sentry_sdk.integrations import ContextVar

# Configure logging
logger = logging.getLogger(__name__)

# ==================== CUSTOM EXCEPTIONS ====================

class StripeDisabledError(RuntimeError):
    """Raised when Stripe is disabled via feature flag."""
    def __init__(self, message: str = None, operation: str = None):
        self.operation = operation
        default_msg = "Stripe is disabled via FEATURE_ENABLE_STRIPE=false"
        if operation:
            default_msg = f"Stripe operation '{operation}' disabled via feature flag"
        super().__init__(message or default_msg)
        self.code = "STRIPE_DISABLED"


class StripeMisconfiguredError(RuntimeError):
    """Raised when Stripe is enabled but misconfigured."""
    def __init__(self, missing_config: str = None):
        self.missing_config = missing_config
        msg = "Stripe is enabled but misconfigured"
        if missing_config:
            msg = f"Stripe misconfigured: Missing {missing_config}"
        super().__init__(msg)
        self.code = "STRIPE_MISCONFIGURED"


# ==================== FEATURE FLAG GUARDS ====================

def stripe_enabled_guard(func: Callable = None, *, 
                        operation_name: str = None,
                        fail_silently: bool = False,
                        log_level: str = "WARNING"):
    """
    Advanced decorator to guard Stripe operations with feature flag checks.
    
    Args:
        func: Function to decorate
        operation_name: Name of the operation for logging/errors
        fail_silently: If True, returns None instead of raising exception
        log_level: Log level to use when Stripe is disabled
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            operation = operation_name or f.__name__
            
            # Check feature flag
            if not feature_flags.ENABLE_STRIPE:
                log_msg = f"Stripe operation blocked: {operation}"
                
                # Structured logging
                logger.log(
                    getattr(logging, log_level),
                    log_msg,
                    extra={
                        "stripe_operation": operation,
                        "feature_flag": "ENABLE_STRIPE",
                        "feature_flag_value": False,
                        "args": str(args)[:200],
                        "kwargs": str(kwargs)[:200]
                    }
                )
                
                # Capture to Sentry for monitoring
                if sentry_sdk.Hub.current:
                    with sentry_sdk.push_scope() as scope:
                        scope.set_tag("stripe_operation", operation)
                        scope.set_tag("feature_flag", "ENABLE_STRIPE")
                        scope.set_context("operation", {
                            "name": operation,
                            "args": str(args)[:500],
                            "kwargs": str(kwargs)[:500]
                        })
                        sentry_sdk.capture_message(
                            f"Stripe operation blocked: {operation}",
                            level="warning"
                        )
                
                if fail_silently:
                    return None
                raise StripeDisabledError(operation=operation)
            
            # Check configuration if enabled
            api_key = os.getenv("STRIPE_SECRET_KEY") or settings.STRIPE_SECRET_KEY
            if not api_key or api_key == "your-secret-key-here":
                error = StripeMisconfiguredError("STRIPE_SECRET_KEY")
                logger.error(
                    "Stripe misconfigured - missing API key",
                    extra={"operation": operation}
                )
                raise error
            
            return f(*args, **kwargs)
        return wrapper
    
    if func:
        return decorator(func)
    return decorator


@contextmanager
def stripe_operation_context(operation_name: str, **context_vars):
    """
    Context manager for Stripe operations with feature flag check.
    
    Example:
        with stripe_operation_context("create_checkout", user_id=123):
            # Stripe operation here
    """
    if not feature_flags.ENABLE_STRIPE:
        raise StripeDisabledError(operation=operation_name)
    
    # Start performance monitoring
    start_time = datetime.now()
    
    # Set Sentry context
    if sentry_sdk.Hub.current:
        with sentry_sdk.configure_scope() as scope:
            scope.set_tag("stripe_operation", operation_name)
            scope.set_context("stripe_context", context_vars)
            scope.set_extra("operation_start", start_time.isoformat())
    
    try:
        logger.info(
            f"Starting Stripe operation: {operation_name}",
            extra={"operation": operation_name, **context_vars}
        )
        
        yield
        
    except Exception as e:
        # Log error with full context
        duration = (datetime.now() - start_time).total_seconds()
        logger.error(
            f"Stripe operation failed: {operation_name}",
            exc_info=True,
            extra={
                "operation": operation_name,
                "duration_seconds": duration,
                "error_type": type(e).__name__,
                "error_message": str(e),
                **context_vars
            }
        )
        raise
        
    finally:
        # Log success
        duration = (datetime.now() - start_time).total_seconds()
        logger.info(
            f"Completed Stripe operation: {operation_name}",
            extra={
                "operation": operation_name,
                "duration_seconds": duration,
                **context_vars
            }
        )


# ==================== CONFIGURATION MANAGEMENT ====================

@dataclass
class StripeConfig:
    """Advanced Stripe configuration with validation."""
    enabled: bool
    api_key: str
    webhook_secret: Optional[str]
    default_currency: str = "usd"
    webhook_tolerance: int = 300
    max_network_retries: int = 2
    timeout: int = 30
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of issues."""
        issues = []
        
        if self.enabled:
            if not self.api_key or self.api_key.startswith("sk_test_"):
                issues.append("Invalid or test API key configured")
            if not self.webhook_secret:
                issues.append("Webhook secret not configured")
        
        return issues
    
    def is_production_ready(self) -> bool:
        """Check if configuration is production-ready."""
        return (
            self.enabled and 
            self.api_key and 
            not self.api_key.startswith("sk_test_") and
            self.webhook_secret is not None
        )


class StripeConfigManager:
    """Singleton manager for Stripe configuration."""
    _instance = None
    _lock = Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._config = None
                cls._instance._last_validation = []
        return cls._instance
    
    def get_config(self) -> StripeConfig:
        """Get current Stripe configuration."""
        if self._config is None:
            self._config = StripeConfig(
                enabled=feature_flags.ENABLE_STRIPE,
                api_key=os.getenv("STRIPE_SECRET_KEY") or settings.STRIPE_SECRET_KEY,
                webhook_secret=os.getenv("STRIPE_WEBHOOK_SECRET") or getattr(settings, "STRIPE_WEBHOOK_SECRET", None),
                default_currency=getattr(settings, "STRIPE_DEFAULT_CURRENCY", "usd"),
                webhook_tolerance=getattr(settings, "STRIPE_WEBHOOK_TOLERANCE", 300),
                max_network_retries=getattr(settings, "STRIPE_MAX_RETRIES", 2),
                timeout=getattr(settings, "STRIPE_TIMEOUT", 30)
            )
            self._last_validation = self._config.validate()
            
            # Log configuration status
            if self._config.enabled:
                logger.info(
                    "Stripe configuration loaded",
                    extra={
                        "config": {
                            "enabled": True,
                            "production_ready": self._config.is_production_ready(),
                            "currency": self._config.default_currency,
                            "validation_issues": self._last_validation
                        }
                    }
                )
            else:
                logger.info("Stripe disabled via feature flag")
        
        return self._config
    
    def validate_config(self) -> Tuple[bool, List[str]]:
        """Validate current configuration."""
        config = self.get_config()
        issues = self._last_validation
        return len(issues) == 0, issues


# ==================== ADVANCED STRIPE SERVICE ====================

class StripeService:
    """
    Advanced Stripe service with feature flag integration, monitoring,
    and graceful degradation.
    """
    
    # Class-level configuration
    _config_manager = StripeConfigManager()
    
    def __init__(self):
        """Initialize Stripe service with configuration validation."""
        self.config = self._config_manager.get_config()
        
        # Initialize Stripe only if enabled and properly configured
        if self.config.enabled:
            stripe.api_key = self.config.api_key
            stripe.max_network_retries = self.config.max_network_retries
            stripe.timeout = self.config.timeout
            
            # Log Stripe client initialization
            logger.info(
                "Stripe client initialized",
                extra={
                    "api_key_prefix": self.config.api_key[:8] + "..." if self.config.api_key else None,
                    "max_retries": stripe.max_network_retries,
                    "timeout": stripe.timeout
                }
            )
    
    # ============ CORE OPERATIONS WITH ADVANCED GUARDS ============
    
    @stripe_enabled_guard(operation_name="create_customer")
    def create_customer(
        self,
        email: str, 
        name: Optional[str] = None,
        phone: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        **kwargs
    ) -> stripe.Customer:
        """Create a Stripe customer with monitoring."""
        with stripe_operation_context("create_customer", email=email):
            try:
                customer_data = {
                    "email": email,
                    "name": name,
                    "phone": phone,
                    "metadata": metadata or {}
                }
                
                # Add idempotency key if provided
                if idempotency_key:
                    customer_data["idempotency_key"] = idempotency_key
                
                # Create customer
                customer = stripe.Customer.create(**customer_data, **kwargs)
                
                # Log success
                logger.info(
                    "Stripe customer created",
                    extra={
                        "customer_id": customer.id,
                        "email": email,
                        "metadata": metadata
                    }
                )
                
                return customer
                
            except stripe.error.StripeError as e:
                logger.error(
                    "Failed to create Stripe customer",
                    exc_info=True,
                    extra={"email": email, "stripe_error": str(e)}
                )
                raise
    
    @stripe_enabled_guard(operation_name="create_checkout_session")
    def create_checkout_session(
        self,
        user_id: str,
        email: str,
        price_id: str,
        success_url: str,
        cancel_url: str,
        mode: str = "subscription",
        customer_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        allow_promotion_codes: bool = True,
        trial_period_days: Optional[int] = None,
        **kwargs
    ) -> str:
        """Create a Stripe checkout session."""
        with stripe_operation_context(
            "create_checkout_session",
            user_id=user_id,
            price_id=price_id,
            mode=mode
        ):
            try:
                session_data = {
                    "customer_email": email if not customer_id else None,
                    "customer": customer_id,
                    "line_items": [{"price": price_id, "quantity": 1}],
                    "mode": mode,
                    "success_url": success_url,
                    "cancel_url": cancel_url,
                    "allow_promotion_codes": allow_promotion_codes,
                    "metadata": {
                        "user_id": user_id,
                        **(metadata or {})
                    }
                }
                
                if trial_period_days:
                    session_data["subscription_data"] = {
                        "trial_period_days": trial_period_days
                    }
                
                session = stripe.checkout.Session.create(**session_data, **kwargs)
                
                logger.info(
                    "Stripe checkout session created",
                    extra={
                        "session_id": session.id,
                        "user_id": user_id,
                        "price_id": price_id,
                        "url": session.url
                    }
                )
                
                return session.url
                
            except stripe.error.StripeError as e:
                logger.error(
                    "Failed to create checkout session",
                    exc_info=True,
                    extra={
                        "user_id": user_id,
                        "price_id": price_id,
                        "stripe_error": str(e)
                    }
                )
                raise
    
    @stripe_enabled_guard(operation_name="create_subscription")
    def create_subscription(
        self,
        customer_id: str, 
        price_id: str, 
        trial_period_days: Optional[int] = None,
        promotion_code: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        expand_payment_intent: bool = True,
        **kwargs
    ) -> stripe.Subscription:
        """Create a subscription."""
        with stripe_operation_context(
            "create_subscription",
            customer_id=customer_id,
            price_id=price_id
        ):
            try:
                subscription_data = {
                    "customer": customer_id,
                    "items": [{"price": price_id}],
                    "metadata": metadata or {},
                    "expand": ["latest_invoice.payment_intent"] if expand_payment_intent else []
                }
                
                if trial_period_days:
                    subscription_data["trial_period_days"] = trial_period_days
                
                if promotion_code:
                    subscription_data["promotion_code"] = promotion_code
                
                if idempotency_key:
                    subscription_data["idempotency_key"] = idempotency_key
                
                subscription = stripe.Subscription.create(**subscription_data, **kwargs)
                
                logger.info(
                    "Stripe subscription created",
                    extra={
                        "subscription_id": subscription.id,
                        "customer_id": customer_id,
                        "price_id": price_id,
                        "status": subscription.status
                    }
                )
                
                return subscription
                
            except stripe.error.StripeError as e:
                logger.error(
                    "Failed to create subscription",
                    exc_info=True,
                    extra={
                        "customer_id": customer_id,
                        "price_id": price_id,
                        "stripe_error": str(e)
                    }
                )
                raise
    
    @stripe_enabled_guard(operation_name="cancel_subscription")
    def cancel_subscription(
        self,
        subscription_id: str,
        cancel_at_period_end: bool = False,
        cancellation_reason: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        **kwargs
    ) -> stripe.Subscription:
        """Cancel a subscription."""
        with stripe_operation_context(
            "cancel_subscription",
            subscription_id=subscription_id
        ):
            try:
                cancel_params = {
                    "cancel_at_period_end": cancel_at_period_end
                }
                
                if cancellation_reason:
                    cancel_params["cancellation_details"] = {
                        "comment": cancellation_reason
                    }
                
                if idempotency_key:
                    cancel_params["idempotency_key"] = idempotency_key
                
                subscription = stripe.Subscription.modify(
                    subscription_id,
                    **cancel_params,
                    **kwargs
                )
                
                logger.info(
                    "Stripe subscription cancelled",
                    extra={
                        "subscription_id": subscription_id,
                        "cancel_at_period_end": cancel_at_period_end,
                        "reason": cancellation_reason
                    }
                )
                
                return subscription
                
            except stripe.error.StripeError as e:
                logger.error(
                    "Failed to cancel subscription",
                    exc_info=True,
                    extra={
                        "subscription_id": subscription_id,
                        "stripe_error": str(e)
                    }
                )
                raise
    
    # ============ WEBHOOK HANDLING ============
    
    @stripe_enabled_guard(operation_name="handle_webhook")
    def handle_webhook(
        self,
        payload: bytes, 
        sig_header: str, 
        webhook_secret: Optional[str] = None,
        tolerance: int = None,
        **kwargs
    ) -> stripe.Event:
        """Handle Stripe webhook event."""
        with stripe_operation_context("handle_webhook"):
            try:
                # Use provided secret or default
                secret = webhook_secret or self.config.webhook_secret
                if not secret:
                    raise StripeMisconfiguredError("STRIPE_WEBHOOK_SECRET")
                
                # Construct event
                event = stripe.Webhook.construct_event(
                    payload, sig_header, secret,
                    tolerance=tolerance or self.config.webhook_tolerance
                )
                
                logger.info(
                    "Stripe webhook received",
                    extra={
                        "event_id": event.id,
                        "event_type": event.type,
                        "livemode": event.livemode
                    }
                )
                
                return event
                
            except ValueError as e:
                logger.error("Invalid webhook payload", exc_info=True)
                raise
            except stripe.error.SignatureVerificationError as e:
                logger.error("Invalid webhook signature", exc_info=True)
                raise
    
    # ============ UTILITY METHODS ============
    
    @stripe_enabled_guard(operation_name="sync_subscription", fail_silently=True)
    def sync_subscription(
        self,
        subscription: Union[str, stripe.Subscription],
        user_id: Optional[int] = None,
        force_update: bool = False
    ) -> Optional[SubscriptionState]:
        """
        Sync subscription to database. Returns None if Stripe is disabled.
        """
        try:
            # Your existing sync logic here
            # This will only run if Stripe is enabled
            
            # For demonstration:
            logger.info(
                "Syncing subscription",
                extra={
                    "subscription_id": subscription if isinstance(subscription, str) else subscription.id,
                    "user_id": user_id
                }
            )
            
            # Return mock or actual SubscriptionState
            return SubscriptionState(
                # Your sync logic
            )
            
        except Exception as e:
            logger.error("Failed to sync subscription", exc_info=True)
            return None
    
    @classmethod
    def get_config_status(cls) -> Dict[str, Any]:
        """Get current Stripe configuration status."""
        config = cls._config_manager.get_config()
        is_valid, issues = cls._config_manager.validate_config()
        
        return {
            "enabled": config.enabled,
            "production_ready": config.is_production_ready(),
            "valid": is_valid,
            "validation_issues": issues,
            "config": {
                "api_key_configured": bool(config.api_key),
                "webhook_secret_configured": bool(config.webhook_secret),
                "default_currency": config.default_currency
            }
        }
    
    @classmethod
    def health_check(cls) -> Dict[str, Any]:
        """
        Comprehensive health check of Stripe integration.
        Returns status and diagnostics.
        """
        status = cls.get_config_status()
        
        # Test connectivity if enabled
        if status["enabled"] and status["valid"]:
            try:
                # Lightweight API call to test connectivity
                stripe.api_key = cls._config_manager.get_config().api_key
                balance = stripe.Balance.retrieve()
                status["connectivity"] = {
                    "connected": True,
                    "available": balance.available[0].amount if balance.available else 0,
                    "pending": balance.pending[0].amount if balance.pending else 0
                }
            except Exception as e:
                status["connectivity"] = {
                    "connected": False,
                    "error": str(e)
                }
        else:
            status["connectivity"] = {"connected": False, "reason": "disabled_or_misconfigured"}
        
        return status


# ==================== FACTORY FUNCTION ====================

def get_stripe_service() -> StripeService:
    """
    Factory function to get Stripe service instance.
    This allows for dependency injection and testing.
    """
    return StripeService()


# ==================== LEGACY COMPATIBILITY ====================

# Create singleton instance for backward compatibility
# This will immediately check feature flags on import
stripe_service = StripeService()

# Legacy function for backward compatibility
def assert_stripe_enabled():
    """Legacy guard function for backward compatibility."""
    if not feature_flags.ENABLE_STRIPE:
        raise StripeDisabledError()


# ==================== DECORATOR FOR EXTERNAL USE ====================

def requires_stripe(func: Callable = None, *, fail_silently: bool = False):
    """
    Decorator for any function that requires Stripe to be enabled.
    Can be used on routes, tasks, or any other functions.
    
    Example:
        @requires_stripe
        def my_billing_function():
            # This will only run if Stripe is enabled
    
        @requires_stripe(fail_silently=True)
        def optional_billing_function():
            # This will return None if Stripe is disabled
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not feature_flags.ENABLE_STRIPE:
                if fail_silently:
                    return None
                raise StripeDisabledError(operation=f.__name__)
            return f(*args, **kwargs)
        return wrapper
    
    if func:
        return decorator(func)
    return decorator