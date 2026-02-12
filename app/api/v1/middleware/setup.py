from flask_cors import CORS

def setup_cors(app):
    CORS(app, resources={r"/*": {"origins": "*"}})

def setup_security_headers(app):
    @app.after_request
    def add_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response

def setup_request_hooks(app):
    @app.before_request
    def before():
        pass
