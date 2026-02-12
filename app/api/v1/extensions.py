# app/extensions.py
"""
Flask extensions initialization module.
Handles initialization and configuration of all Flask extensions with enhanced security.
"""

import logging
from datetime import timedelta

import redis
from flask import jsonify, make_response, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, get_jwt_identity, verify_jwt_in_request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Index, inspect, text

# Initialize extensions
db = SQLAlchemy()
jwt = JWTManager()
cors = CORS()
migrate = Migrate()
mail = Mail()
limiter = None
redis_client = None

logger = logging.getLogger(__name__)


def init_extensions(app):
    """Initialize all Flask extensions with enhanced security and configuration."""
    
    try:
        # Initialize Redis for rate limiting and session management
        init_redis(app)
        
        # Initialize SQLAlchemy
        db.init_app(app)
        logger.info("SQLAlchemy initialized")
        
        # Initialize Flask-Migrate
        migrate.init_app(app, db)
        logger.info("Flask-Migrate initialized")
        
        # Initialize JWT Manager with secure configuration
        jwt.init_app(app)
        configure_jwt(app)
        logger.info("JWT Manager initialized with secure configuration")
        
        # Initialize CORS with security best practices
        init_cors(app)
        logger.info("CORS initialized with security configuration")
        
        # Initialize Flask-Mail
        mail.init_app(app)
        logger.info("Flask-Mail initialized")
        
        # Initialize rate limiter with advanced configuration
        init_rate_limiter(app)
        
        # Setup JWT configuration and callbacks
        setup_jwt_configuration(app)
        setup_jwt_callbacks()
        
        # Create tables only in development or if configured
        if app.config.get('ENVIRONMENT') == 'development' or app.config.get('CREATE_TABLES_ON_START', False):
            create_tables(app)
        
        logger.info("All extensions initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize extensions: {e}")
        if app.config.get('ENVIRONMENT') == 'production':
            raise
        logger.warning("Continuing in development mode despite extension errors")
    
    return app


def configure_jwt(app):
    """Configure JWT settings with security best practices."""
    app.config['JWT_SECRET_KEY'] = app.config.get('SECRET_KEY', 'fallback-secret-key-change-me')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)  # Short-lived access tokens
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)    # Longer-lived refresh tokens
    app.config['JWT_TOKEN_LOCATION'] = ['headers']
    app.config['JWT_HEADER_NAME'] = 'Authorization'
    app.config['JWT_HEADER_TYPE'] = 'Bearer'
    app.config['JWT_ALGORITHM'] = 'HS256'
    app.config['JWT_BLACKLIST_ENABLED'] = True
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Set to True for production with proper CSRF setup
    app.config['JWT_CSRF_IN_COOKIES'] = False
    app.config['JWT_IDENTITY_CLAIM'] = 'sub'
    app.config['JWT_ERROR_MESSAGE_KEY'] = 'error'


def init_cors(app):
    """Initialize CORS with security best practices."""
    cors_config = {
        'origins': app.config.get('CORS_ORIGINS', []),
        'methods': app.config.get('CORS_METHODS', ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']),
        'allow_headers': app.config.get('CORS_HEADERS', ['Content-Type', 'Authorization']),
        'supports_credentials': app.config.get('CORS_SUPPORTS_CREDENTIALS', False),
        'max_age': app.config.get('CORS_MAX_AGE', 600),
    }
    
    # Apply CORS configuration
    cors.init_app(app, **cors_config)


def init_redis(app):
    """Initialize Redis connection for rate limiting and blacklist."""
    global redis_client
    try:
        redis_url = app.config.get('REDIS_URL', 'redis://localhost:6379/0')
        redis_client = redis.from_url(
            redis_url, 
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5,
            retry_on_timeout=True,
            health_check_interval=30
        )
        
        # Test connection with timeout
        redis_client.ping()
        logger.info("Redis initialized successfully")
        
        # Set Redis configuration for better performance
        if app.config.get('ENVIRONMENT') == 'production':
            redis_client.config_set('tcp-keepalive', '300')
            redis_client.config_set('timeout', '0')
        
    except redis.ConnectionError as e:
        logger.error(f"Failed to connect to Redis: {e}")
        if app.config.get('ENVIRONMENT') == 'production':
            logger.warning("Rate limiting and token blacklisting will be disabled without Redis")
            raise
        redis_client = None
    except Exception as e:
        logger.error(f"Unexpected error initializing Redis: {e}")
        redis_client = None


def init_rate_limiter(app):
    """Initialize rate limiter with Redis backend and advanced configuration."""
    global limiter
    
    try:
        def advanced_key_func():
            """Custom key function that provides multi-strategy rate limiting."""
            ip = get_remote_address()
            
            # Strategy 1: IP-based (anonymous users)
            key_parts = [f"ip:{ip}"]
            
            # Strategy 2: User-based (authenticated users)
            try:
                verify_jwt_in_request(optional=True)
                user_id = get_jwt_identity()
                if user_id:
                    key_parts.append(f"user:{user_id}")
            except Exception:
                pass
            
            # Strategy 3: Endpoint-based granularity
            if request.endpoint:
                key_parts.append(f"endpoint:{request.endpoint}")
            
            # Strategy 4: HTTP method differentiation
            key_parts.append(f"method:{request.method}")
            
            return ":".join(key_parts)
        
        # Determine storage backend
        if redis_client:
            storage_uri = app.config.get('REDIS_URL', 'redis://localhost:6379/0')
            logger.info("Using Redis backend for rate limiting")
        else:
            storage_uri = "memory://"
            logger.warning("Using in-memory rate limiting storage - NOT RECOMMENDED FOR PRODUCTION")
        
        # Enhanced default limits with different strategies
        default_limits = [
            "200 per day",
            "50 per hour",
            "10 per minute",
            "5 per 10 seconds"
        ]
        
        # Custom limits based on endpoint patterns
        dynamic_limits = {
            "auth.*": ["10 per minute", "100 per day"],
            "api.*": ["100 per hour", "1000 per day"],
            "public.*": ["500 per hour", "5000 per day"],
            "admin.*": ["5 per minute", "50 per hour"]
        }
        
        # Initialize limiter with comprehensive configuration
        limiter = Limiter(
            app=app,
            key_func=advanced_key_func,
            storage_uri=storage_uri,
            default_limits=default_limits,
            strategy="moving-window",
            headers_enabled=True,
            on_breach=rate_limit_exceeded_handler,
            fail_on_first_breach=False,
            application_limits=app.config.get('APPLICATION_LIMITS', None),
            deduct_when=lambda response: response.status_code != 429
        )
        
        # Register dynamic limits
        for pattern, limits in dynamic_limits.items():
            limiter.limit(limits, key_func=advanced_key_func)(pattern)
        
        # Add global exempt routes
        exempt_routes = app.config.get('RATE_LIMIT_EXEMPT_ROUTES', [])
        for route in exempt_routes:
            limiter.exempt(route)
        
        logger.info("Advanced rate limiter initialized successfully")
        
        # Test rate limiting
        if app.config.get('TEST_RATE_LIMITING', False):
            test_rate_limiting(app)
            
    except Exception as e:
        logger.error(f"Failed to initialize rate limiter: {e}", exc_info=True)
        if app.config.get('ENVIRONMENT') == 'production':
            limiter = Limiter(
                app=app,
                key_func=get_remote_address,
                default_limits=["100 per hour", "1000 per day"],
                storage_uri="memory://",
                headers_enabled=True
            )
            logger.warning("Using fallback rate limiter in production mode")
        else:
            logger.warning("Continuing in development mode without rate limiting")


def rate_limit_exceeded_handler(request_limit):
    """Custom handler for rate limit exceeded."""
    import time
    
    response = make_response(jsonify({
        'error': 'rate_limit_exceeded',
        'message': f'Rate limit exceeded: {request_limit.limit}',
        'retry_after': int(request_limit.reset_at - time.time()),
        'limit': request_limit.limit,
        'remaining': 0,
        'reset': int(request_limit.reset_at)
    }), 429)
    
    # Add rate limit headers
    response.headers['X-RateLimit-Limit'] = request_limit.limit
    response.headers['X-RateLimit-Remaining'] = 0
    response.headers['X-RateLimit-Reset'] = int(request_limit.reset_at)
    response.headers['Retry-After'] = int(request_limit.reset_at - time.time())
    
    return response


def setup_jwt_configuration(app):
    """Configure JWT settings with enhanced claims."""
    
    @jwt.additional_claims_loader
    def add_claims_to_access_token(identity):
        from app.models.user import User
        user = User.query.get(identity)
        if user:
            return {
                'user_id': user.id,
                'email': user.email,
                'role': user.role,
                'permissions': user.get_permissions() if hasattr(user, 'get_permissions') else [],
                'is_verified': user.is_verified,
                'is_active': user.is_active,
                'session_id': user.current_session_id if hasattr(user, 'current_session_id') else None,
                'iss': app.config.get('JWT_ISSUER', 'your-app'),
                'aud': app.config.get('JWT_AUDIENCE', 'your-app-users'),
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': user.last_login.isoformat() if hasattr(user, 'last_login') and user.last_login else None
            }
        return {}


def setup_jwt_callbacks():
    """Setup JWT callbacks for token validation and error handling."""
    
    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        """Check if token is blacklisted with Redis or database fallback."""
        jti = jwt_payload['jti']
        
        # First check Redis for performance
        if redis_client and redis_client.exists(f"blacklist:{jti}"):
            return True
        
        # Fallback to database check
        try:
            from app.models.token_blacklist import TokenBlacklist
            return TokenBlacklist.is_revoked(jti)
        except Exception:
            return False
    
    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'error': 'token_revoked',
            'message': 'The token has been revoked. Please login again.'
        }), 401
    
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'error': 'token_expired',
            'message': 'The token has expired. Please refresh your token.',
            'refresh_url': '/api/auth/refresh'
        }), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({
            'error': 'invalid_token',
            'message': 'Invalid token. Please provide a valid authentication token.'
        }), 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({
            'error': 'authorization_required',
            'message': 'Authentication required. Please provide a valid token.'
        }), 401
    
    @jwt.needs_fresh_token_loader
    def needs_fresh_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'error': 'fresh_token_required',
            'message': 'A fresh token is required for this action.'
        }), 401
    
    logger.info("Advanced JWT callbacks configured")


def create_tables(app):
    """Create database tables with advanced indexes."""
    try:
        with app.app_context():
            db.create_all()
            
            from app.models.user import User
            
            # Define composite and functional indexes
            indexes = [
                Index('idx_users_email_lower', text('lower(email)'), unique=True),
                Index('idx_users_email_active', User.email, User.is_active),
                Index('idx_users_role_active', User.role, User.is_active),
                Index('idx_users_created_at_status', User.created_at, User.subscription_status),
                Index('idx_users_last_login', User.last_login.desc() if hasattr(User, 'last_login') else User.created_at.desc()),
                Index('idx_users_optimized_query', 
                      User.is_active, 
                      User.is_verified, 
                      User.subscription_status,
                      User.created_at.desc()),
            ]
            
            # Create indexes with error handling
            for index in indexes:
                try:
                    inspector = inspect(db.engine)
                    existing_indexes = inspector.get_indexes('users')
                    index_exists = any(idx['name'] == index.name for idx in existing_indexes)
                    
                    if not index_exists:
                        index.create(bind=db.engine)
                        logger.info(f"Created index: {index.name}")
                except Exception as e:
                    logger.warning(f"Failed to create index {index.name}: {e}")
            
            create_foreign_key_indexes()
            logger.info("Database tables and advanced indexes created/verified")
            
    except Exception as e:
        logger.error(f"Failed to create tables: {e}", exc_info=True)
        if app.config.get('ENVIRONMENT') == 'production':
            raise


def create_foreign_key_indexes():
    """Create indexes on foreign key columns for better join performance."""
    try:
        inspector = inspect(db.engine)
        
        for table_name in inspector.get_table_names():
            for fk in inspector.get_foreign_keys(table_name):
                for column in fk['constrained_columns']:
                    index_name = f"idx_{table_name}_{column}_fk"
                    
                    existing_indexes = inspector.get_indexes(table_name)
                    if not any(idx['name'] == index_name for idx in existing_indexes):
                        index = Index(index_name, column)
                        index.create(bind=db.engine)
                        logger.debug(f"Created foreign key index: {index_name}")
                        
    except Exception as e:
        logger.warning(f"Failed to create foreign key indexes: {e}")


def test_rate_limiting(app):
    """Test rate limiting functionality."""
    try:
        with app.test_client() as client:
            for i in range(6):
                response = client.get('/')
                if i == 5 and response.status_code == 429:
                    logger.info("Rate limiting test passed: Request #6 was rate limited")
                    break
    except Exception as e:
        logger.warning(f"Rate limiting test failed: {e}")


def get_redis_client():
    """Get Redis client instance with health check."""
    if redis_client:
        try:
            redis_client.ping()
            return redis_client
        except Exception:
            logger.warning("Redis connection lost")
            return None
    return None


def get_limiter():
    """Get limiter instance."""
    return limiter


def get_rate_limit_info():
    """Get current rate limit configuration."""
    if limiter:
        return {
            'enabled': True,
            'storage_backend': 'redis' if redis_client else 'memory',
            'default_limits': limiter._default_limits,
            'strategy': 'moving-window'
        }
    return {'enabled': False}


# Export extensions for use in other modules
__all__ = [
    'db', 'jwt', 'cors', 'migrate', 'mail', 'limiter', 'redis_client',
    'init_extensions', 'get_redis_client', 'get_limiter', 'get_rate_limit_info'
]