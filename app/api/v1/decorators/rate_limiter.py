from functools import wraps
from flask import request, g
from services.abuse_detector import AbuseDetector, AccountLockedError


def enforce_rate_limit(event_type: str = 'rate_limit'):
    """
    Decorator to enforce rate limiting and abuse detection on endpoints.
    
    Usage:
        @app.route('/api/automation')
        @enforce_rate_limit(event_type='automation')
        def run_automation():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'user'):
                return f(*args, **kwargs)
            
            detector = AbuseDetector()
            
            try:
                # Check if user is locked
                detector.enforce_access(g.user.id)
                
                # Check plan-based limits
                plan_limit = detector.get_plan_limit(g.user.plan)
                # Implement your specific rate limiting logic here
                
                return f(*args, **kwargs)
                
            except AccountLockedError as e:
                from flask import jsonify
                return jsonify({
                    'error': 'Account temporarily locked',
                    'message': str(e),
                    'locked_until': e.locked_until.isoformat(),
                    'remaining_time': e.remaining_time,
                    'code': 'ACCOUNT_LOCKED'
                }), 423  # 423 Locked
            
        return decorated_function
    return decorator