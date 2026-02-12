from flask import request, g, abort
from services.abuse_detector import AbuseDetector


class AbusePreventionMiddleware:
    """Middleware to automatically check for abuse before each request."""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        @app.before_request
        def check_abuse_protection():
            # Skip for certain endpoints
            if request.endpoint in ['static', 'health_check', 'login']:
                return
            
            # Only check if user is authenticated
            if hasattr(g, 'user') and g.user:
                detector = AbuseDetector()
                
                if not detector.check_user_access(g.user.id):
                    abort(423, description="Account temporarily locked due to abuse detection")
        
        @app.after_request
        def track_abuse_events(response):
            # Track failed requests (status 4xx, 5xx)
            if (hasattr(g, 'user') and g.user and 
                response.status_code >= 400 and 
                request.endpoint not in ['static']):
                
                detector = AbuseDetector()
                
                if response.status_code == 429:  # Rate limit
                    detector.record_event(
                        g.user.id, 
                        event_type='rate_limit',
                        severity='high'
                    )
                elif response.status_code >= 500:  # Server errors
                    # Only track if it's likely user-caused
                    if 'automation' in request.endpoint:
                        detector.record_event(
                            g.user.id,
                            event_type='failed_automation',
                            severity='medium'
                        )
            
            return response