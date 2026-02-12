from functools import wraps
from flask import jsonify, g
from typing import Callable, Any
import logging

logger = logging.getLogger(__name__)


def subscription_required(fn: Callable) -> Callable:
    """
    Decorator to enforce subscription requirements for API endpoints.
    Must be used after @jwt_required to ensure current_user is available.
    """
    @wraps(fn)  # Preserves function metadata
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        # Check if user is authenticated (safety check)
        if not hasattr(g, 'current_user') or g.current_user is None:
            logger.warning("Unauthorized access attempt to subscription-protected endpoint")
            return jsonify({
                "error": "Authentication required",
                "code": "AUTH_REQUIRED"
            }), 401
        
        # Check subscription status
        if not hasattr(g.current_user, 'subscription_active'):
            logger.error(f"User model missing subscription_active attribute: {type(g.current_user)}")
            return jsonify({
                "error": "Internal server error",
                "code": "USER_MODEL_ERROR"
            }), 500
        
        # Evaluate subscription status
        if not g.current_user.subscription_active:
            logger.info(f"Subscription required for user: {g.current_user.id}")
            return jsonify({
                "error": "Active subscription required",
                "message": "Please upgrade your subscription to access this feature",
                "code": "SUBSCRIPTION_REQUIRED",
                "upgrade_url": "/pricing"  # Optional: provide upgrade path
            }), 403
        
        # All checks passed, execute the endpoint
        return fn(*args, **kwargs)
    
    return wrapper