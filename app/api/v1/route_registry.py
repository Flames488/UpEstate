# app/route_registry.py
from flask import render_template
import logging

logger = logging.getLogger(__name__)

def register_routes(app):
    """Register all routes and blueprints"""
    
    # Serve frontend index
    @app.route("/")
    def index():
        return render_template("index.html")
    
    # Register API blueprints
    try:
        from app.routes import (
            auth_routes,
            lead_routes,
            dashboard_routes,
            billing_routes,
        )
        
        app.register_blueprint(auth_routes.bp)
        app.register_blueprint(lead_routes.bp)
        app.register_blueprint(dashboard_routes.bp)
        app.register_blueprint(billing_routes.bp)
        
        logger.info("Registered main API blueprints")
        
    except ImportError as e:
        logger.error(f"Failed to import main routes: {e}")
        raise
    
    # Register additional blueprints
    try:
        from app.routes.webhook_routes import webhook_bp
        from app.routes.billing_routes import bp as billing_bp_extra
        
        app.register_blueprint(billing_bp_extra)
        app.register_blueprint(webhook_bp)
        
        logger.info("Registered additional blueprints")
        
    except ImportError as e:
        logger.warning(f"Failed to import additional routes: {e}")
        # Don't raise here as these might be optional
    
    return app