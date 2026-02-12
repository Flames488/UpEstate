"""
Production-hardened configuration management with JWT Cookie-based authentication.
Designed to fail fast with clear error messages. Supports both legacy and modern config.
"""

import os
import sys
import logging
import warnings
from datetime import timedelta
from typing import Dict, Any, Optional, List, Union
from urllib.parse import urlparse
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Environment(str, Enum):
    """Environment types"""
    DEVELOPMENT = "development"
    PRODUCTION = "production"
    TESTING = "testing"
    STAGING = "staging"


class ConfigurationError(Exception):
    """Raised when configuration validation fails"""
    pass


class SecureConfig:
    """
    Advanced secure configuration with JWT Cookie-based authentication.
    Supports both legacy (header-based) and modern (cookie-based) authentication.
    """
    
    # ============================================
    # APPLICATION META & VERSIONING
    # ============================================
    APP_NAME = os.getenv("APP_NAME", "RealEstate Pro")
    APP_VERSION = os.getenv("APP_VERSION", "1.0.0")
    API_VERSION = os.getenv("API_VERSION", "v1")
    TIMEZONE = os.getenv("TIMEZONE", "UTC")
    
    # ============================================
    # ENVIRONMENT & DEBUG
    # ============================================
    ENV = os.getenv("ENV", os.getenv("FLASK_ENV", "development")).lower()
    ENVIRONMENT = ENV  # Alias for compatibility
    DEBUG = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    TESTING = False
    PROPAGATE_EXCEPTIONS = False
    
    # ============================================
    # URL CONFIGURATION
    # ============================================
    @property
    def FRONTEND_URL(self):
        """Lazy-load frontend URL with validation"""
        url = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
        
        # Security: Require HTTPS in production
        if self.ENV == Environment.PRODUCTION and not url.startswith("https://"):
            warnings.warn(f"Frontend URL should use HTTPS in production: {url}")
        
        return url
    
    @property
    def BACKEND_URL(self):
        """Lazy-load backend URL with validation"""
        url = os.getenv("BACKEND_URL", "http://localhost:5000").rstrip("/")
        
        # Security: Require HTTPS in production
        if self.ENV == Environment.PRODUCTION and not url.startswith("https://"):
            warnings.warn(f"Backend URL should use HTTPS in production: {url}")
        
        return url
    
    # ============================================
    # SECURITY KEYS - CRITICAL
    # ============================================
    @property
    def SECRET_KEY(self):
        """Lazy-load secret key with validation"""
        key = os.getenv("SECRET_KEY")
        if not key:
            if self.ENV == Environment.PRODUCTION:
                raise ConfigurationError("SECRET_KEY is required in production")
            warnings.warn("SECRET_KEY not set, using development fallback")
            return "dev-secret-key-change-immediately-in-production"
        
        if len(key) < 64 and self.ENV == Environment.PRODUCTION:
            raise ConfigurationError("SECRET_KEY must be at least 64 characters in production")
        
        return key
    
    @property
    def JWT_SECRET_KEY(self):
        """Lazy-load JWT secret key with validation"""
        key = os.getenv("JWT_SECRET_KEY", self.SECRET_KEY)  # Fallback to SECRET_KEY
        
        if not key:
            if self.ENV == Environment.PRODUCTION:
                raise ConfigurationError("JWT_SECRET_KEY is required in production")
            warnings.warn("JWT_SECRET_KEY not set, using development fallback")
            return "dev-jwt-secret-key-change-immediately"
        
        if len(key) < 64 and self.ENV == Environment.PRODUCTION:
            raise ConfigurationError("JWT_SECRET_KEY must be at least 64 characters in production")
        
        return key
    
    SECRET_KEY_ALT = os.getenv("SECRET_KEY_ALT")  # For key rotation
    SECURITY_PASSWORD_SALT = os.getenv("SECURITY_PASSWORD_SALT", "password-salt-change-me")
    
    # ============================================
    # DATABASE CONFIGURATION
    # ============================================
    @property
    def SQLALCHEMY_DATABASE_URI(self):
        """Lazy-load database URI with validation"""
        uri = os.getenv("DATABASE_URL")
        
        if not uri:
            if self.ENV == Environment.PRODUCTION:
                raise ConfigurationError("DATABASE_URL is required in production")
            # Default for development
            uri = "sqlite:///realestate.db"
        
        # Validate database URL
        parsed = urlparse(uri)
        
        # Security: Reject SQLite in production
        if self.ENV == Environment.PRODUCTION and parsed.scheme == "sqlite":
            raise ConfigurationError("SQLite is not allowed in production. Use PostgreSQL or MySQL.")
        
        # Security: Reject insecure connections in production
        if self.ENV == Environment.PRODUCTION and "localhost" in uri and not parsed.scheme.startswith("postgres"):
            warnings.warn("Using localhost database in production may be insecure")
        
        return uri
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_size": int(os.getenv("DATABASE_POOL_SIZE", "10")),
        "max_overflow": int(os.getenv("DATABASE_MAX_OVERFLOW", "20")),
        "pool_recycle": int(os.getenv("DATABASE_POOL_RECYCLE", "3600")),
        "pool_timeout": int(os.getenv("DATABASE_POOL_TIMEOUT", "30")),
        "pool_pre_ping": True,
        "echo": os.getenv("SQLALCHEMY_ECHO", "False").lower() == "true",
    }
    
    # ============================================
    # PAYMENT PROVIDERS
    # ============================================
    @property
    def PAYSTACK_SECRET_KEY(self):
        """Lazy-load Paystack secret key"""
        key = os.getenv("PAYSTACK_SECRET_KEY")
        if not key and self.ENV == Environment.PRODUCTION:
            warnings.warn("PAYSTACK_SECRET_KEY not set")
        return key or ""
    
    PAYSTACK_PUBLIC_KEY = os.getenv("PAYSTACK_PUBLIC_KEY", "")
    
    @property
    def STRIPE_SECRET_KEY(self):
        """Lazy-load Stripe secret key with validation"""
        key = os.getenv("STRIPE_SECRET_KEY")
        
        if not key:
            if self.ENV == Environment.PRODUCTION:
                raise ConfigurationError("STRIPE_SECRET_KEY is required in production")
            return "sk_test_xxx"  # Development fallback
        
        # Security: Detect test keys in production
        if self.ENV == Environment.PRODUCTION and key.startswith("sk_test"):
            raise ConfigurationError("Stripe test key detected in production!")
        
        return key
    
    @property
    def STRIPE_WEBHOOK_SECRET(self):
        """Lazy-load Stripe webhook secret"""
        secret = os.getenv("STRIPE_WEBHOOK_SECRET")
        
        if not secret and self.ENV == Environment.PRODUCTION:
            raise ConfigurationError("STRIPE_WEBHOOK_SECRET is required in production")
        
        return secret or ""
    
    STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "pk_test_xxx")
    STRIPE_BASIC_PRICE_ID = os.getenv("STRIPE_BASIC_PRICE_ID", "")
    STRIPE_PRO_PRICE_ID = os.getenv("STRIPE_PRO_PRICE_ID", "")
    STRIPE_ENTERPRISE_PRICE_ID = os.getenv("STRIPE_ENTERPRISE_PRICE_ID", "")
    STRIPE_CONNECT_CLIENT_ID = os.getenv("STRIPE_CONNECT_CLIENT_ID", "")
    
    STRIPE_WEBHOOK_SUPPORTED_EVENTS = [
        'customer.subscription.created',
        'customer.subscription.updated',
        'customer.subscription.deleted',
        'invoice.paid',
        'invoice.payment_failed'
    ]
    
    # ============================================
    # JWT CONFIGURATION - DUAL MODE (Cookies + Headers)
    # ============================================
    # Token location priority: cookies first, headers as fallback
    JWT_TOKEN_LOCATION = ["cookies", "headers"] if os.getenv("JWT_USE_HEADERS", "False").lower() == "true" else ["cookies"]
    
    # Cookie names
    JWT_ACCESS_COOKIE_NAME = "access_token"
    JWT_REFRESH_COOKIE_NAME = "refresh_token"
    
    # Token expiration
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    JWT_ALGORITHM = "HS256"
    JWT_IDENTITY_CLAIM = "sub"
    JWT_USER_CLAIMS = "user_claims"
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ["access", "refresh"]
    
    # Cookie security settings
    @property
    def JWT_COOKIE_SECURE(self):
        """Secure cookies configuration"""
        if self.ENV == Environment.PRODUCTION:
            return True
        # Allow configuration override in development
        return os.getenv("JWT_COOKIE_SECURE", "False").lower() == "true"
    
    JWT_COOKIE_HTTPONLY = True
    
    @property
    def JWT_COOKIE_SAMESITE(self):
        """SameSite cookie policy"""
        if self.ENV == Environment.PRODUCTION:
            return os.getenv("JWT_COOKIE_SAMESITE", "None")
        # Safer defaults for development
        return os.getenv("JWT_COOKIE_SAMESITE", "Lax")
    
    @property
    def JWT_COOKIE_DOMAIN(self):
        """Cookie domain for cross-domain authentication"""
        return os.getenv("SESSION_COOKIE_DOMAIN")
    
    # CSRF Protection
    JWT_COOKIE_CSRF_PROTECT = os.getenv("JWT_COOKIE_CSRF_PROTECT", "False").lower() == "true"
    JWT_CSRF_IN_COOKIES = True if JWT_COOKIE_CSRF_PROTECT else False
    JWT_CSRF_CHECK_FORM = True if JWT_COOKIE_CSRF_PROTECT else False
    JWT_CSRF_METHODS = ["POST", "PUT", "PATCH", "DELETE"] if JWT_COOKIE_CSRF_PROTECT else []
    
    @property
    def JWT_ACCESS_CSRF_COOKIE_NAME(self):
        return f"{self.JWT_ACCESS_COOKIE_NAME}_csrf" if self.JWT_COOKIE_CSRF_PROTECT else ""
    
    @property
    def JWT_REFRESH_CSRF_COOKIE_NAME(self):
        return f"{self.JWT_REFRESH_COOKIE_NAME}_csrf" if self.JWT_COOKIE_CSRF_PROTECT else ""
    
    JWT_ACCESS_COOKIE_PATH = "/"
    JWT_REFRESH_COOKIE_PATH = "/api/auth/refresh"
    
    # ============================================
    # SESSION CONFIGURATION
    # ============================================
    @property
    def SESSION_COOKIE_HTTPONLY(self):
        return True
    
    @property
    def SESSION_COOKIE_SECURE(self):
        return self.ENV == Environment.PRODUCTION
    
    @property
    def SESSION_COOKIE_SAMESITE(self):
        return "None" if self.ENV == Environment.PRODUCTION else "Lax"
    
    SESSION_COOKIE_NAME = "realestate_session"
    SESSION_TYPE = "redis" if os.getenv("REDIS_URL") else "filesystem"
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = "session:"
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    # ============================================
    # CORS CONFIGURATION
    # ============================================
    @property
    def CORS_SUPPORTS_CREDENTIALS(self):
        return True  # Required for cookie-based auth
    
    @property
    def CORS_ORIGINS(self):
        """Lazy-load CORS origins with intelligent defaults"""
        origins = os.getenv("CORS_ORIGINS", "")
        
        if origins:
            # Split comma-separated origins
            origin_list = [origin.strip() for origin in origins.split(",") if origin.strip()]
            
            # Security: Block wildcard in production
            if self.ENV == Environment.PRODUCTION and "*" in origin_list:
                raise ConfigurationError("CORS wildcard ('*') is not allowed in production")
            
            # Add frontend URL if not already present
            if self.FRONTEND_URL not in origin_list:
                origin_list.append(self.FRONTEND_URL)
            
            return origin_list
        
        # Default behavior based on environment
        if self.ENV == Environment.PRODUCTION:
            return [self.FRONTEND_URL]
        elif self.ENV == Environment.DEVELOPMENT:
            return ["*"]  # Allow all in development
        else:
            return [self.FRONTEND_URL]
    
    CORS_EXPOSE_HEADERS = [
        "Content-Range", 
        "X-Total-Count",
        "X-CSRF-Token",
        "Set-Cookie"
    ]
    
    CORS_ALLOW_HEADERS = [
        "Content-Type",
        "Authorization",
        "X-CSRF-Token",
        "X-Requested-With",
        "Accept",
        "Origin",
        "Cookie"
    ]
    
    CORS_MAX_AGE = 600
    
    # ============================================
    # REDIS CONFIGURATION
    # ============================================
    @property
    def REDIS_URL(self):
        """Lazy-load Redis URL"""
        url = os.getenv("REDIS_URL")
        
        if not url:
            if self.ENV == Environment.PRODUCTION:
                # Try to construct from component parts
                host = os.getenv("REDIS_HOST", "localhost")
                port = os.getenv("REDIS_PORT", "6379")
                db = os.getenv("REDIS_DB", "0")
                password = os.getenv("REDIS_PASSWORD", "")
                
                if password:
                    url = f"redis://:{password}@{host}:{port}/{db}"
                else:
                    url = f"redis://{host}:{port}/{db}"
            else:
                # Default for development
                return "redis://localhost:6379/0"
        
        return url
    
    @property
    def SESSION_REDIS(self):
        """Redis connection for sessions"""
        return self.REDIS_URL
    
    REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
    
    # ============================================
    # EMAIL CONFIGURATION
    # ============================================
    @property
    def MAIL_USERNAME(self):
        username = os.getenv("MAIL_USERNAME")
        if not username and self.ENV == Environment.PRODUCTION:
            warnings.warn("MAIL_USERNAME is recommended in production")
        return username or ""
    
    @property
    def MAIL_PASSWORD(self):
        password = os.getenv("MAIL_PASSWORD")
        if not password and self.ENV == Environment.PRODUCTION:
            warnings.warn("MAIL_PASSWORD is recommended in production")
        return password or ""
    
    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "True").lower() == "true"
    MAIL_USE_SSL = os.getenv("MAIL_USE_SSL", "False").lower() == "true"
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", "noreply@realestatepro.com")
    MAIL_MAX_EMAILS_PER_DAY = int(os.getenv("MAIL_MAX_EMAILS_PER_DAY", "1000"))
    MAIL_SUPPRESS_SEND = os.getenv("MAIL_SUPPRESS_SEND", "False").lower() == "true"
    
    # ============================================
    # RATE LIMITING
    # ============================================
    RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "True").lower() == "true"
    RATE_LIMIT_DEFAULTS = {
        "default": "100 per hour",
        "auth": "10 per minute",
        "api": "1000 per day",
        "payment": "30 per minute",
    }
    
    @property
    def RATE_LIMIT_STORAGE_URI(self):
        uri = os.getenv("RATE_LIMIT_STORAGE_URI")
        if not uri and self.REDIS_URL:
            return self.REDIS_URL.replace("/0", "/1")  # Different DB index
        return uri or "memory://"
    
    # ============================================
    # FILE UPLOADS
    # ============================================
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_FILE_UPLOAD_SIZE", "10485760"))  # 10MB
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", os.path.join(os.getcwd(), "uploads"))
    ALLOWED_EXTENSIONS = set(
        os.getenv("ALLOWED_EXTENSIONS", ".pdf,.jpg,.jpeg,.png,.doc,.docx").split(",")
    )
    
    # ============================================
    # SECURITY HEADERS
    # ============================================
    SECURITY_HEADERS = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload" if self.ENV == Environment.PRODUCTION else "",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://js.stripe.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https://*.stripe.com; "
            "connect-src 'self' https://api.stripe.com; "
            "frame-src 'self' https://js.stripe.com https://hooks.stripe.com;"
            "form-action 'self';"
        ) if self.ENV == Environment.PRODUCTION else "",
        "Permissions-Policy": (
            "geolocation=(), microphone=(), camera=(), "
            "payment=(), usb=(), magnetometer=(), gyroscope=()"
        ),
    }
    
    # ============================================
    # BUSINESS LOGIC
    # ============================================
    ADMIN_EMAILS = [
        email.strip() 
        for email in os.getenv("ADMIN_EMAILS", "admin@realestatepro.com").split(",")
        if email.strip()
    ]
    SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL", "support@realestatepro.com")
    COMPANY_NAME = os.getenv("COMPANY_NAME", "RealEstate Pro")
    
    PAYMENT_FAILURE_RETRY_ATTEMPTS = 3
    PAYMENT_FAILURE_RETRY_DELAY = 24 * 3600  # 24 hours
    ADMIN_ALERT_THRESHOLD = int(os.getenv("ADMIN_ALERT_THRESHOLD", "3"))
    
    # ============================================
    # FEATURE FLAGS
    # ============================================
    ENABLE_MAINTENANCE_MODE = os.getenv("ENABLE_MAINTENANCE_MODE", "False").lower() == "true"
    ENABLE_REGISTRATION = os.getenv("ENABLE_REGISTRATION", "True").lower() == "true"
    ENABLE_EMAIL_VERIFICATION = os.getenv("ENABLE_EMAIL_VERIFICATION", "True").lower() == "true"
    ENABLE_2FA = os.getenv("ENABLE_2FA", "False").lower() == "true"
    ENABLE_API_DOCS = os.getenv("ENABLE_API_DOCS", "True").lower() == "true"
    
    # ============================================
    # MONITORING & LOGGING
    # ============================================
    LOG_LEVEL = os.getenv("LOGGING_LEVEL", "INFO").upper()
    LOG_FILE = os.getenv("LOG_FILE_PATH", "app.log")
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(process)d - %(message)s"
    
    SENTRY_DSN = os.getenv("SENTRY_DSN")
    METRICS_ENABLED = os.getenv("METRICS_ENABLED", "False").lower() == "true"
    
    # ============================================
    # INITIALIZATION & VALIDATION
    # ============================================
    def __init__(self):
        """Initialize and validate configuration"""
        self._validate_environment()
        self._validate_security()
        self._validate_cookie_settings()
        
        logger.info(f"Configuration loaded for {self.ENV} environment")
        if self.ENV == Environment.DEVELOPMENT:
            logger.warning("⚠️  Development mode with relaxed security")
    
    def _validate_environment(self):
        """Validate environment settings"""
        valid_environments = [env.value for env in Environment]
        
        if self.ENV not in valid_environments:
            raise ConfigurationError(
                f"Invalid ENV/FLASK_ENV: {self.ENV}. "
                f"Must be one of: {', '.join(valid_environments)}"
            )
        
        if self.DEBUG and self.ENV == Environment.PRODUCTION:
            warnings.warn("DEBUG mode is enabled in production! This is a security risk.")
    
    def _validate_security(self):
        """Validate security-critical settings"""
        if self.ENV == Environment.PRODUCTION:
            # Check for insecure configurations
            if self.CORS_ORIGINS == ["*"]:
                raise ConfigurationError("CORS wildcard is not allowed in production!")
            
            if self.STRIPE_SECRET_KEY.startswith("sk_test"):
                raise ConfigurationError("Stripe test key detected in production!")
    
    def _validate_cookie_settings(self):
        """Validate cookie-based authentication settings"""
        if self.JWT_COOKIE_SAMESITE == "None" and not self.JWT_COOKIE_SECURE:
            warnings.warn(
                "JWT_COOKIE_SAMESITE='None' requires JWT_COOKIE_SECURE=True. "
                "Cookies may be rejected by browsers."
            )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to safe dictionary"""
        config_dict = {}
        
        for key in dir(self):
            if not key.startswith("_") and key.isupper() and not callable(getattr(self, key)):
                try:
                    value = getattr(self, key)
                    
                    # Mask sensitive values
                    if any(sensitive in key.lower() for sensitive in 
                          ["key", "secret", "password", "token", "auth", "csrf"]):
                        if isinstance(value, str) and value:
                            config_dict[key] = f"***{value[-4:]}" if len(value) > 4 else "***"
                        else:
                            config_dict[key] = "***"
                    else:
                        config_dict[key] = value
                except:
                    config_dict[key] = "<computed>"
        
        return config_dict
    
    def get_jwt_config(self) -> Dict[str, Any]:
        """Get JWT configuration for Flask-JWT-Extended"""
        return {
            "token_location": self.JWT_TOKEN_LOCATION,
            "secret_key": self.JWT_SECRET_KEY,
            "access_token_expires": self.JWT_ACCESS_TOKEN_EXPIRES,
            "refresh_token_expires": self.JWT_REFRESH_TOKEN_EXPIRES,
            "algorithm": self.JWT_ALGORITHM,
            "identity_claim": self.JWT_IDENTITY_CLAIM,
            "user_claims_key": self.JWT_USER_CLAIMS,
            "cookie_secure": self.JWT_COOKIE_SECURE,
            "cookie_httponly": self.JWT_COOKIE_HTTPONLY,
            "cookie_samesite": self.JWT_COOKIE_SAMESITE,
            "cookie_domain": self.JWT_COOKIE_DOMAIN,
            "cookie_csrf_protect": self.JWT_COOKIE_CSRF_PROTECT,
            "csrf_in_cookies": self.JWT_CSRF_IN_COOKIES,
            "csrf_methods": self.JWT_CSRF_METHODS,
            "access_cookie_name": self.JWT_ACCESS_COOKIE_NAME,
            "refresh_cookie_name": self.JWT_REFRESH_COOKIE_NAME,
            "access_cookie_path": self.JWT_ACCESS_COOKIE_PATH,
            "refresh_cookie_path": self.JWT_REFRESH_COOKIE_PATH,
        }
    
    def __repr__(self) -> str:
        """Safe string representation"""
        from pprint import pformat
        return pformat(self.to_dict(), indent=2)


class DevelopmentConfig(SecureConfig):
    """Development configuration with relaxed settings"""
    
    def __init__(self):
        super().__init__()
        
        # Override environment-specific settings
        self.DEBUG = True
        self.PROPAGATE_EXCEPTIONS = True
        self.JWT_COOKIE_SECURE = False
        self.JWT_COOKIE_CSRF_PROTECT = False
        self.JWT_COOKIE_SAMESITE = "Lax"
        self.SESSION_COOKIE_SECURE = False
        self.RATE_LIMIT_ENABLED = False
        self.CORS_ORIGINS = ["*"]
        self.MAIL_SUPPRESS_SEND = True
        self.ENABLE_EMAIL_VERIFICATION = False
        
        logger.info("Development configuration loaded with relaxed security")


class ProductionConfig(SecureConfig):
    """Production configuration with maximum security"""
    
    def __init__(self):
        super().__init__()
        
        # Ensure strict settings
        self.DEBUG = False
        self.PROPAGATE_EXCEPTIONS = False
        self.JWT_COOKIE_SECURE = True
        self.JWT_COOKIE_CSRF_PROTECT = os.getenv("JWT_COOKIE_CSRF_PROTECT", "True").lower() == "true"
        self.JWT_COOKIE_SAMESITE = "None"
        self.SESSION_COOKIE_SECURE = True
        self.RATE_LIMIT_ENABLED = True
        
        # Strict CORS for production
        if not os.getenv("CORS_ORIGINS"):
            self.CORS_ORIGINS = [self.FRONTEND_URL]
        
        logger.info("Production configuration loaded with maximum security")


class TestingConfig(SecureConfig):
    """Testing configuration"""
    
    def __init__(self):
        self.ENV = Environment.TESTING
        self.DEBUG = True
        self.TESTING = True
        
        # Testing-specific settings
        self.SQLALCHEMY_DATABASE_URI = "sqlite:///test.db"
        self.JWT_COOKIE_SECURE = False
        self.JWT_COOKIE_CSRF_PROTECT = False
        self.SESSION_COOKIE_SECURE = False
        self.RATE_LIMIT_ENABLED = False
        self.CORS_ORIGINS = ["*"]
        self.MAIL_SUPPRESS_SEND = True
        
        # Skip full initialization for testing
        logger.info("Testing configuration loaded")


# Configuration factory
def get_config(env: str = None) -> SecureConfig:
    """Get configuration based on environment"""
    if env is None:
        env = os.getenv("ENV", os.getenv("FLASK_ENV", "development")).lower()
    
    config_map = {
        Environment.DEVELOPMENT: DevelopmentConfig,
        Environment.PRODUCTION: ProductionConfig,
        Environment.TESTING: TestingConfig,
        "staging": ProductionConfig,  # Staging uses production config
    }
    
    config_class = config_map.get(env)
    if not config_class:
        # Try to match case-insensitively
        for key, cls in config_map.items():
            if key.lower() == env.lower():
                config_class = cls
                break
    
    if not config_class:
        raise ConfigurationError(f"Unknown environment: {env}")
    
    return config_class()


# Legacy compatibility layer
class Config(SecureConfig):
    """Legacy compatibility class"""
    pass


# Global configuration instance
config: SecureConfig = get_config()

# Command-line interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Configuration management")
    parser.add_argument("--show", action="store_true", help="Show current configuration")
    parser.add_argument("--env", help="Set environment for validation")
    parser.add_argument("--jwt", action="store_true", help="Show JWT configuration")
    parser.add_argument("--security", action="store_true", help="Show security settings")
    parser.add_argument("--validate", action="store_true", help="Validate configuration")
    
    args = parser.parse_args()
    
    if args.show:
        print("🔧 Current Configuration:")
        print(config)
    elif args.jwt:
        print("🔐 JWT Configuration:")
        for key, value in config.get_jwt_config().items():
            print(f"  {key}: {value}")
    elif args.security:
        print("🛡️ Security Settings:")
        print(f"  Environment: {config.ENV}")
        print(f"  Debug: {config.DEBUG}")
        print(f"  JWT Token Location: {config.JWT_TOKEN_LOCATION}")
        print(f"  JWT Cookie Secure: {config.JWT_COOKIE_SECURE}")
        print(f"  JWT Cookie SameSite: {config.JWT_COOKIE_SAMESITE}")
        print(f"  JWT CSRF Protection: {config.JWT_COOKIE_CSRF_PROTECT}")
        print(f"  CORS Origins: {config.CORS_ORIGINS}")
        print(f"  CORS Credentials: {config.CORS_SUPPORTS_CREDENTIALS}")
    elif args.validate:
        env = args.env or config.ENV
        test_config = get_config(env)
        print(f"✅ Configuration validated for {env} environment")
    else:
        print(f"Environment: {config.ENV}")
        print(f"Frontend URL: {config.FRONTEND_URL}")
        print(f"Backend URL: {config.BACKEND_URL}")
        print(f"Database: {config.SQLALCHEMY_DATABASE_URI[:50]}...")
        print(f"JWT Mode: {'Cookies' if 'cookies' in config.JWT_TOKEN_LOCATION else 'Headers'}")