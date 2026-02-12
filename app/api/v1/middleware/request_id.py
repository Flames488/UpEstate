import uuid
from flask import g, request


REQUEST_ID_HEADER = "X-Request-ID"


def init_request_id_middleware(app):
    """
    Initialize request ID middleware for a Flask app.
    Attaches a unique correlation ID to every request.
    """
    
    @app.before_request
    def before_request():
        """Attach request ID at the start of each request."""
        incoming = request.headers.get(REQUEST_ID_HEADER)
        g.request_id = incoming or str(uuid.uuid4())
    
    @app.after_request
    def after_request(response):
        """Add request ID to response headers."""
        response.headers[REQUEST_ID_HEADER] = g.get("request_id", "")
        return response


# Alternative explicit functions if you prefer manual control
def assign_request_id():
    """
    Explicit function to attach request ID (for manual use).
    """
    incoming = request.headers.get(REQUEST_ID_HEADER)
    g.request_id = incoming or str(uuid.uuid4())


def add_request_id_header(response):
    """
    Explicit function to add request ID to response (for manual use).
    """
    response.headers[REQUEST_ID_HEADER] = g.get("request_id", "")
    return response