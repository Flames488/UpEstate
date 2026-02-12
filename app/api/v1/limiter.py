# app/limiter.py
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import request
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
import os
import redis

def create_limiter(app=None):
    """Create and configure rate limiter based on app configuration"""
    
    # Default configuration
    default_limits = ["200 per day", "50 per hour"]
    storage_uri = "memory://"
    
    # If app is provided during creation, use its config
    if app:
        # Use new rate limiting config variables if available, fall back to legacy ones
        default_limits = app.config.get('RATE_LIMIT_DEFAULTS', 
                                       app.config.get('RATELIMIT_DEFAULT', "200 per day; 50 per hour"))
        
        # Handle both string and list formats
        if isinstance(default_limits, str):
            default_limits = default_limits.split('; ')
        
        # Try to use Redis if available
        try:
            redis_url = app.config.get('REDIS_URL', 'redis://localhost:6379/0')
            storage_uri = redis_url
            app.logger.info(f"Using Redis for rate limiting: {redis_url}")
        except Exception as e:
            # Fallback to config or in-memory storage
            storage_uri = app.config.get('RATE_LIMIT_STORAGE_URI', 
                                        app.config.get('RATELIMIT_STORAGE_URL', storage_uri))
            if storage_uri == "memory://":
                app.logger.warning("Using in-memory rate limiting - not recommended for production")
    
    # Create limiter instance
    limiter = Limiter(
        key_func=get_user_identifier,
        default_limits=default_limits,
        storage_uri=storage_uri,
        strategy="fixed-window",  # or "moving-window"
        headers_enabled=True,
        fail_on_first_breach=True
    )
    
    # Initialize with app if provided
    if app:
        limiter.init_app(app)
    
    return limiter


def create_no_op_limiter():
    """Create a no-operation limiter for development when rate limiting fails"""
    class NoOpLimiter:
        def __init__(self):
            self.enabled = False
            
        def limit(self, *args, **kwargs):
            def decorator(f):
                return f
            return decorator
            
        def exempt(self, *args, **kwargs):
            def decorator(f):
                return f
            return decorator
            
        def init_app(self, app):
            app.extensions['limiter'] = self
            
    return NoOpLimiter()


# Custom key function for rate limiting
def get_user_identifier():
    """Get identifier for rate limiting (prioritizes user ID over IP)"""
    # Try to get user ID from JWT
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
        if user_id:
            return f"user:{user_id}"
    except Exception:
        pass
    
    # Fallback to IP address
    return get_remote_address()


# Create a global limiter instance (will be configured later)
# This allows importing limiter before app is initialized
limiter = Limiter(
    key_func=get_user_identifier,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    headers_enabled=True
)


# Export for use in other modules
__all__ = ['limiter', 'create_limiter', 'create_no_op_limiter', 'get_user_identifier']