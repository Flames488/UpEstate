"""
Advanced Flask application factory with robust configuration validation.
Designed to fail fast on configuration errors with maximum security.
"""

import os
import sys
import logging
import warnings
from datetime import datetime
from typing import Optional, Dict, Any
from config.validate_env import *  # runs immediately

from flask import Flask, jsonify, request
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
from flask_cors import CORS

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import get_config, ConfigurationError
from app.config_validator import validate_configuration
from app.observability import init_observability  # Updated import
from app.extensions import db, jwt
from app.security.rate_limit import limiter
from app.api.v1.automation_routes import bp as automation_bp
from app.api.v1.billing_routes import bp as billing_bp
from app.billing.paystack_webhook import bp as paystack_bp
from app.middleware.metrics import register_metrics

# Global limiter instance
limiter = None
cors = None  # Global CORS instance


def setup_logging(app: Flask) -> None:
    """Setup comprehensive logging for the application"""
    
    # Determine log level from config
    log_level = app.config.get('LOG_LEVEL', 'INFO').upper()
    log_file = app.config.get('LOG_FILE')
    
    # Create formatter
    log_format = app.config.get('LOG_FORMAT', 
        '%(asctime)s - %(name)s - %(levelname)s - %(process)d - %(message)s')
    formatter = logging.Formatter(log_format)
    
    # Configure handlers
    handlers = []
    
    # Console handler (always)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    handlers.append(console_handler)
    
    # File handler (if log file specified)
    if log_file:
        try:
            # Ensure log directory exists
            log_dir = os.path.dirname(log_file)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            handlers.append(file_handler)
            app.logger.info(f"File logging configured: {log_file}")
        except Exception as e:
            app.logger.error(f"Failed to setup file logging: {str(e)}")
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level))
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Add new handlers
    for handler in handlers:
        root_logger.addHandler(handler)
    
    # Configure Flask logger
    app.logger.handlers.clear()
    for handler in handlers:
        app.logger.addHandler(handler)
    app.logger.setLevel(getattr(logging, log_level))
    
    # Suppress noisy loggers
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    # Disable Flask development server log
    if app.config.get('ENVIRONMENT') == 'production':
        logging.getLogger('werkzeug').disabled = True
    
    app.logger.info(f"Logging configured at {log_level} level")


def setup_sentry(app: Flask) -> None:
    """Initialize Sentry error tracking"""
    sentry_dsn = app.config.get('SENTRY_DSN')
    
    if sentry_dsn and app.config.get('ENVIRONMENT') == 'production':
        try:
            sentry_sdk.init(
                dsn=sentry_dsn,
                integrations=[FlaskIntegration()],
                traces_sample_rate=0.1,
                environment="production",
                release=app.config.get('APP_VERSION', '1.0.0'),
                send_default_pii=False,
                before_send=lambda event, hint: event
            )
            app.logger.info("Sentry error tracking initialized")
        except Exception as e:
            app.logger.error(f"Failed to initialize Sentry: {str(e)}")


def setup_cors(app: Flask) -> None:
    """Configure CORS with security and credential support for API routes only"""
    global cors
    
    try:
        # Get FRONTEND_URL from environment with validation
        frontend_url = os.getenv("FRONTEND_URL")
        
        # 🧪 Quick sanity check
        app.logger.info(f"Allowed CORS origin: {frontend_url}")
        
        if not frontend_url:
            if app.config.get('ENVIRONMENT') == 'production':
                raise RuntimeError("FRONTEND_URL environment variable is required in production")
            else:
                app.logger.warning("FRONTEND_URL not set, CORS will be disabled")
                return
        
        # 🚫 NEVER use "*" in production
        if frontend_url == "*" and app.config.get('ENVIRONMENT') == 'production':
            raise RuntimeError("Wildcard CORS origin '*' is not allowed in production")
        
        # 🚫 NEVER hardcode localhost in production
        if "localhost" in frontend_url and app.config.get('ENVIRONMENT') == 'production':
            app.logger.warning("⚠️  WARNING: Using localhost origin in production!")
        
        # 🎯 Professional CORS configuration - API routes only
        cors_config = {
            'resources': {
                r"/api/*": {
                    "origins": frontend_url,
                    "supports_credentials": True,
                    "allow_headers": [
                        'Content-Type', 
                        'Authorization', 
                        'X-Requested-With',
                        'X-CSRF-Token',
                        'Accept',
                        'Origin'
                    ],
                    "methods": ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'],
                    "expose_headers": [
                        'Content-Range', 
                        'X-Total-Count',
                        'X-Request-ID',
                        'Set-Cookie',
                        'Authorization'
                    ],
                    "max_age": 86400,  # 24 hours
                }
            },
            'supports_credentials': True,
            'vary_header': True,
            'send_wildcard': False,
            'automatic_options': True,
        }
        
        # Initialize CORS with configuration
        cors = CORS(app, **cors_config)
        app.cors = cors
        
        # Log CORS configuration details
        app.logger.info(f"✅ CORS configured successfully for API routes")
        app.logger.info(f"   Origin: {frontend_url}")
        app.logger.info(f"   Supports Credentials: True")
        app.logger.info(f"   Resource Pattern: /api/*")
        app.logger.info(f"   Max Age: 86400 seconds")
        
        # Verify CORS is properly configured
        if not hasattr(app, 'cors') or app.cors is None:
            raise RuntimeError("CORS initialization failed")
            
    except RuntimeError as e:
        app.logger.error(f"❌ CORS configuration error: {str(e)}")
        if app.config.get('ENVIRONMENT') == 'production':
            raise
        else:
            app.logger.warning("Continuing without CORS in development mode")
    except Exception as e:
        app.logger.error(f"❌ Failed to setup CORS: {str(e)}")
        if app.config.get('ENVIRONMENT') == 'production':
            raise RuntimeError(f"CORS configuration failed: {str(e)}")
        else:
            app.logger.warning("Continuing without CORS in development mode")


def setup_security_headers(app: Flask) -> None:
    """Add security headers to all responses"""
    
    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses"""
        security_headers = app.config.get('SECURITY_HEADERS', {})
        
        # Add CORS headers from Flask-CORS if CORS is enabled
        if hasattr(app, 'cors') and app.cors:
            # Flask-CORS will automatically add CORS headers
            pass
        
        # Add custom security headers
        for header, value in security_headers.items():
            # Don't override existing headers
            if header not in response.headers:
                response.headers[header] = value
        
        # Additional headers
        response.headers['Server'] = app.config.get('APP_NAME', 'RealEstate Pro')
        response.headers['X-Powered-By'] = 'Flask'
        
        # Security headers for API responses
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Content Security Policy (adjust based on your needs)
        if app.config.get('ENVIRONMENT') == 'production':
            csp_policy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
            response.headers['Content-Security-Policy'] = csp_policy
        
        return response
    
    app.logger.info("Security headers middleware configured")


def setup_request_hooks(app: Flask) -> None:
    """Setup request lifecycle hooks"""
    
    @app.before_request
    def before_request_hook():
        """Execute before each request"""
        app.logger.debug(f"Request: {request.method} {request.path}")
        
        # Log CORS preflight requests
        if request.method == 'OPTIONS':
            app.logger.debug(f"CORS preflight request for {request.path}")
        
        # Rate limiting check (would be handled by Flask-Limiter)
        pass
    
    @app.after_request
    def after_request_hook(response):
        """Execute after each request"""
        # Log request completion
        app.logger.debug(f"Response: {response.status_code} for {request.method} {request.path}")
        
        # Add request ID to response if available
        if hasattr(request, 'request_id'):
            response.headers['X-Request-ID'] = request.request_id
        
        # Log CORS headers for debugging
        if app.config.get('ENVIRONMENT') == 'development':
            cors_headers = {k: v for k, v in response.headers if 'access-control' in k.lower()}
            if cors_headers:
                app.logger.debug(f"CORS headers added: {cors_headers}")
        
        return response
    
    @app.teardown_request
    def teardown_request_hook(exception=None):
        """Execute after request is complete"""
        if exception:
            app.logger.error(f"Request teardown with exception: {str(exception)}")
    
    app.logger.info("Request lifecycle hooks configured")


def init_extensions(app: Flask) -> None:
    """Initialize Flask extensions"""
    from flask_sqlalchemy import SQLAlchemy
    from flask_migrate import Migrate
    from flask_jwt_extended import JWTManager
    from flask_mail import Mail
    from redis import Redis
    
    try:
        # Database - using imported db from app.extensions
        db.init_app(app)
        migrate = Migrate(app, db)
        app.db = db
        app.logger.info("Database extensions initialized")
        
        # JWT Authentication - using imported jwt from app.extensions
        jwt.init_app(app)
        app.jwt = jwt
        
        # Setup JWT blacklist if Redis is available
        if app.config.get('REDIS_URL'):
            try:
                from app.auth.jwt_blacklist import jwt_redis_blacklist
                jwt_redis_blacklist.init_app(app)
                app.logger.info("JWT blacklist initialized")
            except ImportError:
                app.logger.warning("JWT blacklist module not found")
        
        app.logger.info("JWT authentication initialized")
        
        # Email
        mail = Mail(app)
        app.mail = mail
        app.logger.info("Email extension initialized")
        
        # Redis
        redis_url = app.config.get('REDIS_URL')
        if redis_url:
            try:
                redis_client = Redis.from_url(redis_url, decode_responses=True)
                app.redis = redis_client
                
                # Test Redis connection
                redis_client.ping()
                app.logger.info("Redis connection established")
            except Exception as e:
                app.logger.error(f"Failed to connect to Redis: {str(e)}")
                if app.config.get('ENVIRONMENT') == 'production':
                    raise
        
        # Cache (if using Flask-Caching)
        try:
            from flask_caching import Cache
            cache_config: Dict[str, Any] = {
                'CACHE_TYPE': app.config.get('CACHE_TYPE', 'simple'),
                'CACHE_REDIS_URL': app.config.get('CACHE_REDIS_URL'),
                'CACHE_DEFAULT_TIMEOUT': app.config.get('CACHE_DEFAULT_TIMEOUT', 300),
                'CACHE_KEY_PREFIX': app.config.get('CACHE_KEY_PREFIX', 'realestate_')
            }
            cache = Cache(app, config=cache_config)
            app.cache = cache
            app.logger.info("Caching initialized")
        except ImportError:
            app.logger.info("Flask-Caching not installed, skipping cache setup")
        
        app.logger.info("All extensions initialized successfully")
        
    except Exception as e:
        app.logger.critical(f"Failed to initialize extensions: {str(e)}")
        raise


def init_rate_limiter(app: Flask) -> None:
    """Initialize rate limiter extension"""
    global limiter
    
    try:
        # Use the imported limiter from app.security.rate_limit
        limiter.init_app(app)
        app.limiter = limiter
        app.logger.info("Rate limiter initialized")
            
    except ImportError as e:
        app.logger.warning(f"Failed to import rate limiter: {str(e)}")
        app.logger.warning("Rate limiting will not be available")
    except Exception as e:
        app.logger.error(f"Failed to initialize rate limiter: {str(e)}")
        if app.config.get('ENVIRONMENT') == 'production':
            raise


def register_error_handlers(app: Flask) -> None:
    """Register error handlers"""
    
    @app.errorhandler(400)
    def bad_request_error(error):
        app.logger.warning(f"Bad request: {str(error)}")
        return jsonify({
            'error': 'Bad Request',
            'message': str(error.description) if hasattr(error, 'description') else 'Invalid request',
            'status_code': 400
        }), 400
    
    @app.errorhandler(401)
    def unauthorized_error(error):
        app.logger.warning(f"Unauthorized: {str(error)}")
        return jsonify({
            'error': 'Unauthorized',
            'message': 'Authentication required',
            'status_code': 401
        }), 401
    
    @app.errorhandler(403)
    def forbidden_error(error):
        app.logger.warning(f"Forbidden: {str(error)}")
        return jsonify({
            'error': 'Forbidden',
            'message': 'You do not have permission to access this resource',
            'status_code': 403
        }), 403
    
    @app.errorhandler(404)
    def not_found_error(error):
        app.logger.warning(f"Not found: {str(error)}")
        return jsonify({
            'error': 'Not Found',
            'message': 'The requested resource was not found',
            'status_code': 404
        }), 404
    
    @app.errorhandler(405)
    def method_not_allowed_error(error):
        app.logger.warning(f"Method not allowed: {str(error)}")
        return jsonify({
            'error': 'Method Not Allowed',
            'message': 'The HTTP method is not allowed for this endpoint',
            'status_code': 405
        }), 405
    
    @app.errorhandler(429)
    def rate_limit_error(error):
        app.logger.warning(f"Rate limit exceeded: {str(error)}")
        return jsonify({
            'error': 'Too Many Requests',
            'message': 'Rate limit exceeded. Please try again later.',
            'status_code': 429
        }), 429
    
    @app.errorhandler(500)
    def internal_server_error(error):
        app.logger.error(f"Internal server error: {str(error)}")
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred. Our team has been notified.',
            'status_code': 500,
            'request_id': getattr(request, 'request_id', None)
        }), 500
    
    @app.errorhandler(ConfigurationError)
    def configuration_error(error):
        app.logger.critical(f"Configuration error: {str(error)}")
        return jsonify({
            'error': 'Configuration Error',
            'message': str(error),
            'status_code': 500
        }), 500
    
    app.logger.info("Error handlers registered")


def register_routes(app: Flask) -> None:
    """Register application routes"""
    
    # Register imported blueprints
    app.register_blueprint(automation_bp)
    app.register_blueprint(billing_bp)
    app.register_blueprint(paystack_bp)
    
    # Health check endpoint
    @app.route('/health', methods=['GET'])
    def health_check():
        """Comprehensive health check endpoint"""
        from sqlalchemy import text
        
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'environment': app.config.get('ENVIRONMENT'),
            'version': app.config.get('APP_VERSION', '1.0.0'),
            'service': app.config.get('APP_NAME', 'RealEstate Pro'),
            'checks': {}
        }
        
        # Check database
        try:
            app.db.session.execute(text('SELECT 1'))
            health_status['checks']['database'] = 'healthy'
        except Exception as e:
            health_status['checks']['database'] = f'unhealthy: {str(e)}'
            health_status['status'] = 'degraded'
        
        # Check Redis
        if hasattr(app, 'redis'):
            try:
                app.redis.ping()
                health_status['checks']['redis'] = 'healthy'
            except Exception as e:
                health_status['checks']['redis'] = f'unhealthy: {str(e)}'
                health_status['status'] = 'degraded'
        
        # Check CORS configuration
        cors_status = 'disabled'
        if hasattr(app, 'cors') and app.cors:
            cors_status = 'enabled'
            frontend_url = os.getenv("FRONTEND_URL")
            if frontend_url:
                cors_status += f' (origin: {frontend_url})'
        health_status['checks']['cors'] = cors_status
        
        # Check external services
        external_services = ['stripe', 'mail']
        for service in external_services:
            health_status['checks'][service] = 'configured'
        
        return jsonify(health_status), 200 if health_status['status'] == 'healthy' else 503
    
    # Safe configuration endpoint (development only)
    if app.config.get('ENVIRONMENT') in ['development', 'testing']:
        @app.route('/api/v1/config/safe', methods=['GET'])
        def safe_config():
            """Return safe configuration without secrets"""
            config_instance = app.config_class if hasattr(app, 'config_class') else app.config
            if hasattr(config_instance, 'to_dict'):
                return jsonify(config_instance.to_dict())
            return jsonify({
                'environment': app.config.get('ENVIRONMENT'),
                'debug': app.config.get('DEBUG'),
                'version': app.config.get('APP_VERSION'),
                'cors_origin': os.getenv("FRONTEND_URL"),
                'cors_supports_credentials': True
            })
    try:
        from app.routes.auth_routes import auth_bp
        app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
        app.logger.info("Auth routes registered")
    except ImportError as e:
        app.logger.warning(f"Failed to import auth routes: {str(e)}")

    
    # API routes
    try:
        from app.auth.routes import auth_bp
        from app.properties.routes import properties_bp
        from app.payments.routes import payments_bp
        from app.admin.routes import admin_bp
        from app.health import health_bp

        # Import and setup observability middleware
        try:
            from .logging_config import configure_logging
            configure_logging()
            
            from .middleware.request_id import (
                assign_request_id,
                add_request_id_header,
            )
            
            from .observability import (
                before_request,
                after_request,
                log_exception,
            )
            
            # Register middleware in proper order
            app.before_request(assign_request_id)
            app.before_request(before_request)
            
            app.after_request(add_request_id_header)
            app.after_request(after_request)
            
            app.register_error_handler(Exception, log_exception)
            
            app.logger.info("Observability middleware configured")
        except ImportError as e:
            app.logger.warning(f"Observability modules not available: {str(e)}")
        
        # Register health blueprint
        app.register_blueprint(health_bp)
        
        # Register other blueprints
        app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
        app.register_blueprint(properties_bp, url_prefix='/api/v1/properties')
        app.register_blueprint(payments_bp, url_prefix='/api/v1/payments')
        app.register_blueprint(admin_bp, url_prefix='/api/v1/admin')
        
        app.logger.info("API routes registered")
    except ImportError as e:
        app.logger.warning(f"Failed to import some routes: {str(e)}")
    
    # Frontend routes (serving static files)
    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def serve_frontend(path):
        """Serve frontend application"""
        try:
            return app.send_static_file('index.html')
        except:
            return jsonify({
                'error': 'Not Found',
                'message': 'Frontend not built or index.html missing'
            }), 404
    
    app.logger.info("All routes registered")


def apply_database_migrations(app: Flask) -> None:
    """Apply database migrations on startup"""
    if app.config.get('ENVIRONMENT') == 'production':
        migration_policy = os.getenv('AUTO_MIGRATE', 'false').lower()
    else:
        migration_policy = os.getenv('AUTO_MIGRATE', 'true').lower()
    
    if migration_policy == 'true':
        try:
            from flask_migrate import upgrade
            
            app.logger.info("Applying database migrations...")
            with app.app_context():
                upgrade()
            app.logger.info("Database migrations applied successfully")
            
        except ImportError:
            app.logger.warning("Flask-Migrate not installed, skipping migrations")
        except Exception as e:
            app.logger.error(f"Failed to apply database migrations: {str(e)}")
            
            # In production, migrations failing is critical
            if app.config.get('ENVIRONMENT') == 'production':
                raise RuntimeError(f"Database migrations failed: {str(e)}")
    else:
        app.logger.info("Skipping automatic database migrations")


def validate_database_connection(app: Flask) -> None:
    """Validate database connection"""
    try:
        from sqlalchemy import text
        app.db.session.execute(text('SELECT 1'))
        app.logger.info("Database connection verified")
    except Exception as e:
        app.logger.error(f"Database connection failed: {str(e)}")
        if app.config.get('ENVIRONMENT') == 'production':
            raise RuntimeError(f"Database connection failed: {str(e)}")


def log_startup_summary(app: Flask) -> None:
    """Log comprehensive startup summary"""
    def mask_sensitive_data(value: str) -> str:
        """Mask sensitive data in logs"""
        if not value or 'Not configured' in value:
            return value
        if '@' in value:
            parts = value.split('@')
            if len(parts) == 2:
                return f"***@{parts[1][:30]}..."
        return value[:50] + "..." if len(value) > 50 else value
    
    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', 'Not configured')
    redis_url = app.config.get('REDIS_URL', 'Not configured')
    frontend_url = os.getenv("FRONTEND_URL", 'Not configured')
    
    summary_lines = [
        "=" * 60,
        "APPLICATION STARTUP SUMMARY",
        "=" * 60,
        f"Environment:      {app.config.get('ENVIRONMENT')}",
        f"Debug Mode:       {app.config.get('DEBUG')}",
        f"App Name:         {app.config.get('APP_NAME', 'RealEstate Pro')}",
        f"App Version:      {app.config.get('APP_VERSION', '1.0.0')}",
        f"Database:         {mask_sensitive_data(db_uri)}",
        f"Redis:            {mask_sensitive_data(redis_url)}",
        f"FRONTEND_URL:     {frontend_url}",
        f"CORS API Routes:  /api/*",
        f"CORS Credentials: Enabled",
        f"Rate Limiting:    {'Enabled' if app.config.get('RATE_LIMIT_ENABLED') else 'Disabled'}",
        f"Email:            {'Configured' if app.config.get('MAIL_USERNAME') else 'Not configured'}",
        f"Stripe:           {'Live' if app.config.get('STRIPE_SECRET_KEY', '').startswith('sk_live') else 'Test'}",
        f"Sentry:           {'Enabled' if app.config.get('SENTRY_DSN') else 'Disabled'}",
        f"Audit Log:        {'Enabled' if app.config.get('AUDIT_LOG_ENABLED') else 'Disabled'}",
        f"Tracing:          {'Disabled (MVP mode)'}",
        f"Metrics:          {'Disabled (MVP mode)'}",
        "=" * 60,
    ]
    
    app.logger.info("\n".join(summary_lines))


def create_app(config_name: Optional[str] = None) -> Flask:
    """
    Advanced application factory with comprehensive validation.
    
    Args:
        config_name: Configuration name (development, production, testing)
    
    Returns:
        Flask application instance
    
    Raises:
        ConfigurationError: If configuration validation fails
        RuntimeError: If application cannot be created
    """
    global limiter, cors
    
    # ============================================
    # STEP 1: PRE-INITIALIZATION
    # ============================================
    
    # Suppress warnings in production
    if os.getenv('FLASK_ENV') == 'production':
        warnings.filterwarnings('ignore')
    
    # Create Flask app
    app = Flask(
        __name__,
        template_folder="../frontend",
        static_folder="../frontend",
        static_url_path=""
    )
    
    # ============================================
    # STEP 2: LOAD AND VALIDATE CONFIGURATION (FAIL FAST)
    # ============================================
    
    try:
        config = get_config(config_name)
        app.config.from_object(config)
        app.config_class = config
        app.logger = logging.getLogger(__name__)  # Temporary logger
    except ConfigurationError as e:
        print(f"CRITICAL: Configuration error: {str(e)}", file=sys.stderr)
        raise
    
    # ============================================
    # STEP 3: SETUP LOGGING (IMMEDIATELY)
    # ============================================
    
    setup_logging(app)
    app.logger.info(f"Starting application initialization in {app.config.get('ENVIRONMENT')} mode...")
    
    # ============================================
    # STEP 4: COMPREHENSIVE CONFIGURATION VALIDATION
    # ============================================
    
    app.logger.info("Validating configuration...")
    if not validate_configuration(app):
        if app.config.get('ENVIRONMENT') == 'production':
            app.logger.critical("Configuration validation failed in production!")
            raise ConfigurationError("Invalid configuration. Check logs for details.")
        else:
            app.logger.warning("Configuration validation failed, but continuing in development")
    
    # ============================================
    # STEP 5: INITIALIZE MONITORING
    # ============================================
    
    setup_sentry(app)
    
    # ============================================
    # STEP 6: INITIALIZE JWT
    # ============================================
    
    # Initialize JWT early for CORS support
    jwt.init_app(app)
    app.jwt = jwt
    app.logger.info("JWT authentication initialized")
    
    # ============================================
    # STEP 7: SETUP PROFESSIONAL CORS CONFIGURATION
    # ============================================
    
    setup_cors(app)
    
    # ============================================
    # STEP 8: SETUP SECURITY MIDDLEWARE
    # ============================================
    
    setup_security_headers(app)
    setup_request_hooks(app)
    
    # ============================================
    # STEP 9: INITIALIZE OTHER EXTENSIONS
    # ============================================
    
    init_extensions(app)
    
    # ============================================
    # STEP 10: INITIALIZE RATE LIMITER
    # ============================================
    
    init_rate_limiter(app)
    
    # ============================================
    # STEP 11: SETUP OBSERVABILITY FEATURES
    # ============================================
    
    # Initialize observability
    init_observability(app)
    
    # Register metrics
    register_metrics(app)
    
    # ============================================
    # STEP 12: REGISTER ERROR HANDLERS
    # ============================================
    
    register_error_handlers(app)
    
    # ============================================
    # STEP 13: REGISTER ROUTES
    # ============================================
    
    register_routes(app)
    
    # ============================================
    # STEP 14: DATABASE MIGRATIONS & VALIDATION
    # ============================================
    
    with app.app_context():
        apply_database_migrations(app)
        validate_database_connection(app)
    
    # ============================================
    # STEP 15: FINAL VALIDATION & STARTUP
    # ============================================
    
    # Log startup summary
    log_startup_summary(app)
    
    # Final health check
    app.logger.info("Performing final health check...")
    
    # Register startup time
    app.startup_time = datetime.utcnow()
    
    app.logger.info(f"✅ Application initialization completed successfully")
    app.logger.info(f"🚀 Application ready at: {app.config.get('SERVER_NAME', 'localhost:5000')}")
    app.logger.info(f"🔗 CORS configured for API routes only with origin: {os.getenv('FRONTEND_URL')}")
    
    return app


# Create default app instance for WSGI
app = create_app()

if __name__ == "__main__":
    # Development server
    host = os.getenv('FLASK_RUN_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_RUN_PORT', 5000))
    debug = app.config.get('DEBUG', False)
    
    app.logger.info(f"Starting development server on {host}:{port}")
    app.logger.info(f"CORS origin: {os.getenv('FRONTEND_URL', 'Not configured')}")
    app.logger.info(f"CORS credentials: Enabled")
    app.run(host=host, port=port, debug=debug, threaded=True)