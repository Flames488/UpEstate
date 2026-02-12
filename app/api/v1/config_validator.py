
"""
Configuration Validation Module
Validates all environment variables and configuration settings.
Designed to fail fast with detailed error messages.
"""

import os
import sys
import logging
import re
import secrets
import json
import socket
import urllib.parse
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ValidationLevel(Enum):
    """Validation severity levels"""
    CRITICAL = "CRITICAL"  # Must be valid, app won't start
    WARNING = "WARNING"    # Should be valid, but app can start
    INFO = "INFO"          # Informational only


@dataclass
class ValidationRule:
    """Rule for validating a configuration variable"""
    name: str
    level: ValidationLevel
    validator: callable
    message: str
    default_value: Any = None
    required: bool = False


@dataclass
class ValidationResult:
    """Result of validation"""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    infos: List[str] = field(default_factory=list)


class ConfigValidator:
    """Advanced configuration validator with dependency checking"""
    
    def __init__(self, app=None):
        self.app = app
        self.validation_results = ValidationResult(is_valid=True)
        self.validators = self._initialize_validators()
        
    def _initialize_validators(self) -> Dict[str, ValidationRule]:
        """Initialize all validation rules"""
        return {
            # Security - Critical
            'SECRET_KEY': ValidationRule(
                name='SECRET_KEY',
                level=ValidationLevel.CRITICAL,
                validator=self._validate_secret_key,
                message="SECRET_KEY must be at least 64 characters and cryptographically secure",
                required=True
            ),
            'JWT_SECRET_KEY': ValidationRule(
                name='JWT_SECRET_KEY',
                level=ValidationLevel.CRITICAL,
                validator=self._validate_secret_key,
                message="JWT_SECRET_KEY must be at least 64 characters and cryptographically secure",
                required=True
            ),
            
            # Database - Critical
            'DATABASE_URL': ValidationRule(
                name='DATABASE_URL',
                level=ValidationLevel.CRITICAL,
                validator=self._validate_database_url,
                message="DATABASE_URL must be a valid database connection string",
                required=True
            ),
            
            # Redis - Critical for production
            'REDIS_URL': ValidationRule(
                name='REDIS_URL',
                level=ValidationLevel.CRITICAL,
                validator=self._validate_redis_url,
                message="REDIS_URL must be a valid Redis connection string",
                required=False  # Not required for development
            ),
            
            # Stripe - Critical for payment processing
            'STRIPE_SECRET_KEY': ValidationRule(
                name='STRIPE_SECRET_KEY',
                level=ValidationLevel.CRITICAL,
                validator=self._validate_stripe_key,
                message="STRIPE_SECRET_KEY must be a valid Stripe secret key",
                required=True
            ),
            'STRIPE_WEBHOOK_SECRET': ValidationRule(
                name='STRIPE_WEBHOOK_SECRET',
                level=ValidationLevel.CRITICAL,
                validator=lambda x: len(x) >= 32,
                message="STRIPE_WEBHOOK_SECRET must be at least 32 characters",
                required=True
            ),
            
            # Email - Critical for notifications
            'MAIL_USERNAME': ValidationRule(
                name='MAIL_USERNAME',
                level=ValidationLevel.CRITICAL,
                validator=self._validate_email,
                message="MAIL_USERNAME must be a valid email address",
                required=True
            ),
            'MAIL_PASSWORD': ValidationRule(
                name='MAIL_PASSWORD',
                level=ValidationLevel.CRITICAL,
                validator=lambda x: len(x) >= 8,
                message="MAIL_PASSWORD must be at least 8 characters",
                required=True
            ),
            
            # CORS - Warning if too permissive
            'CORS_ORIGINS': ValidationRule(
                name='CORS_ORIGINS',
                level=ValidationLevel.WARNING,
                validator=self._validate_cors_origins,
                message="CORS_ORIGINS should not be '*' in production",
                required=False,
                default_value="*"
            ),
            
            # Feature Flags - Informational
            'FLASK_ENV': ValidationRule(
                name='FLASK_ENV',
                level=ValidationLevel.INFO,
                validator=lambda x: x in ['development', 'production', 'testing'],
                message="FLASK_ENV must be one of: development, production, testing",
                required=False,
                default_value="development"
            ),
        }
    
    def _validate_secret_key(self, value: str) -> bool:
        """Validate that a secret key is cryptographically secure"""
        if not value or len(value) < 64:
            return False
        
        # Check for common insecure patterns
        insecure_patterns = [
            'secret', 'password', 'key', 'default', 'changeme',
            '123456', 'abcdef', 'test', 'demo'
        ]
        
        value_lower = value.lower()
        for pattern in insecure_patterns:
            if pattern in value_lower:
                return False
        
        # Check entropy (simple check)
        if len(set(value)) < 32:  # Low entropy
            return False
            
        return True
    
    def _validate_database_url(self, value: str) -> bool:
        """Validate database connection URL"""
        try:
            parsed = urllib.parse.urlparse(value)
            
            # Check scheme
            valid_schemes = ['postgresql', 'postgres', 'mysql', 'sqlite']
            if parsed.scheme not in valid_schemes:
                return False
            
            # For production, require proper database (not sqlite)
            env = os.getenv('FLASK_ENV', 'development')
            if env == 'production' and parsed.scheme == 'sqlite':
                logger.warning("SQLite is not recommended for production!")
                return False  # Fail in production
            
            return True
        except:
            return False
    
    def _validate_redis_url(self, value: str) -> bool:
        """Validate Redis connection URL"""
        try:
            parsed = urllib.parse.urlparse(value)
            return parsed.scheme == 'redis'
        except:
            return False
    
    def _validate_stripe_key(self, value: str) -> bool:
        """Validate Stripe API key format"""
        if not value:
            return False
        
        # Check for test keys in production
        env = os.getenv('FLASK_ENV', 'development')
        if env == 'production' and value.startswith('sk_test'):
            logger.error("Stripe test key detected in production!")
            return False
        
        # Basic format validation
        if value.startswith('sk_live_') or value.startswith('sk_test_'):
            return len(value) > 20
        
        return False
    
    def _validate_email(self, value: str) -> bool:
        """Validate email address format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, value)) if value else False
    
    def _validate_cors_origins(self, value: str) -> bool:
        """Validate CORS origins configuration"""
        env = os.getenv('FLASK_ENV', 'development')
        
        if env == 'production':
            if value == '*':
                logger.error("CORS set to '*' in production - this is a security risk!")
                return False
            
            # Check if origins are valid URLs
            origins = [origin.strip() for origin in value.split(',')]
            for origin in origins:
                if not (origin.startswith('https://') or origin.startswith('http://localhost')):
                    logger.warning(f"Non-HTTPS origin in production: {origin}")
        
        return True
    
    def _check_database_connection(self, url: str) -> bool:
        """Test database connection"""
        try:
            # This would be implemented based on your database driver
            # For now, return True if URL is valid
            return self._validate_database_url(url)
        except Exception as e:
            logger.error(f"Database connection test failed: {str(e)}")
            return False
    
    def _check_redis_connection(self, url: str) -> bool:
        """Test Redis connection"""
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname or 'localhost'
            port = parsed.port or 6379
            
            # Try to connect to Redis
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)  # 3 second timeout
            result = sock.connect_ex((host, port))
            sock.close()
            
            return result == 0
        except Exception as e:
            logger.error(f"Redis connection test failed: {str(e)}")
            return False
    
    def _check_email_configuration(self) -> bool:
        """Test email configuration by connecting to SMTP server"""
        try:
            import smtplib
            
            server = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
            port = int(os.getenv('MAIL_PORT', 587))
            username = os.getenv('MAIL_USERNAME')
            password = os.getenv('MAIL_PASSWORD')
            
            if not (username and password):
                return False
            
            # Test connection (without actually sending email)
            with smtplib.SMTP(server, port, timeout=10) as smtp:
                smtp.ehlo()
                if os.getenv('MAIL_USE_TLS', 'True').lower() == 'true':
                    smtp.starttls()
                    smtp.ehlo()
                # Don't login here to avoid rate limiting
                
            return True
        except Exception as e:
            logger.warning(f"Email configuration test failed (may be okay): {str(e)}")
            return False  # Warning, not critical
    
    def validate_all(self, fail_fast: bool = True) -> ValidationResult:
        """Validate all configuration variables"""
        logger.info("Starting comprehensive configuration validation...")
        
        # Reset results
        self.validation_results = ValidationResult(is_valid=True)
        
        # Get current environment
        env = os.getenv('FLASK_ENV', 'development')
        logger.info(f"Validating configuration for {env} environment")
        
        # Validate each variable
        for var_name, rule in self.validators.items():
            value = os.getenv(var_name, rule.default_value)
            
            # Skip if not required and not set
            if not rule.required and not value:
                continue
            
            # Check if variable exists
            if rule.required and not value:
                self._add_error(f"Required environment variable '{var_name}' is not set")
                if fail_fast:
                    return self.validation_results
                continue
            
            # Validate value
            try:
                is_valid = rule.validator(value)
            except Exception as e:
                self._add_error(f"Validator for '{var_name}' failed: {str(e)}")
                is_valid = False
            
            # Handle validation result
            if not is_valid:
                if rule.level == ValidationLevel.CRITICAL:
                    self._add_error(f"{var_name}: {rule.message}")
                    if fail_fast:
                        return self.validation_results
                elif rule.level == ValidationLevel.WARNING:
                    self._add_warning(f"{var_name}: {rule.message}")
                else:
                    self._add_info(f"{var_name}: {rule.message}")
            else:
                logger.debug(f"✓ {var_name} validation passed")
        
        # Run connection tests for production
        if env == 'production':
            self._run_connection_tests()
        
        # Check for security anti-patterns
        self._check_security_antipatterns()
        
        # Generate configuration report
        self._generate_report()
        
        return self.validation_results
    
    def _run_connection_tests(self):
        """Run connection tests for external services"""
        logger.info("Running connection tests for external services...")
        
        # Test database connection
        db_url = os.getenv('DATABASE_URL')
        if db_url and self._validate_database_url(db_url):
            if not self._check_database_connection(db_url):
                self._add_warning("Cannot connect to database. Check connection parameters.")
        
        # Test Redis connection
        redis_url = os.getenv('REDIS_URL')
        if redis_url and self._validate_redis_url(redis_url):
            if not self._check_redis_connection(redis_url):
                self._add_warning("Cannot connect to Redis. Some features may be degraded.")
        
        # Test email configuration
        if not self._check_email_configuration():
            self._add_warning("Email configuration may be incorrect. Notifications may fail.")
    
    def _check_security_antipatterns(self):
        """Check for security anti-patterns in configuration"""
        env = os.getenv('FLASK_ENV', 'development')
        
        # Check for debug mode in production
        if env == 'production' and os.getenv('FLASK_DEBUG', '').lower() == 'true':
            self._add_error("FLASK_DEBUG is enabled in production!")
        
        # Check for weak secrets
        weak_secrets = []
        for var in ['SECRET_KEY', 'JWT_SECRET_KEY', 'SECURITY_PASSWORD_SALT']:
            value = os.getenv(var)
            if value and len(value) < 32:
                weak_secrets.append(var)
        
        if weak_secrets:
            self._add_error(f"Weak secrets detected: {', '.join(weak_secrets)}. Must be at least 32 characters.")
        
        # Check for default passwords
        default_passwords = {
            'password': 'MAIL_PASSWORD',
            'changeme': 'SECRET_KEY',
            'secret': 'JWT_SECRET_KEY',
        }
        
        for default, var in default_passwords.items():
            value = os.getenv(var, '').lower()
            if default in value:
                self._add_error(f"Default password pattern detected in {var}")
    
    def _add_error(self, message: str):
        """Add an error message"""
        logger.error(f"❌ {message}")
        self.validation_results.errors.append(message)
        self.validation_results.is_valid = False
    
    def _add_warning(self, message: str):
        """Add a warning message"""
        logger.warning(f"⚠️  {message}")
        self.validation_results.warnings.append(message)
    
    def _add_info(self, message: str):
        """Add an info message"""
        logger.info(f"ℹ️  {message}")
        self.validation_results.infos.append(message)
    
    def _generate_report(self):
        """Generate a configuration validation report"""
        if not self.validation_results.errors and not self.validation_results.warnings:
            logger.info("✅ All configuration checks passed!")
            return
        
        report = ["=" * 60, "CONFIGURATION VALIDATION REPORT", "=" * 60]
        
        if self.validation_results.errors:
            report.append("\n❌ ERRORS (must be fixed):")
            for error in self.validation_results.errors:
                report.append(f"  • {error}")
        
        if self.validation_results.warnings:
            report.append("\n⚠️  WARNINGS (should be addressed):")
            for warning in self.validation_results.warnings:
                report.append(f"  • {warning}")
        
        if self.validation_results.infos:
            report.append("\nℹ️  INFO (for your information):")
            for info in self.validation_results.infos:
                report.append(f"  • {info}")
        
        report.append("=" * 60)
        
        logger.info("\n".join(report))
    
    def validate_configuration(self, app) -> bool:
        """Main validation function to be called from app factory"""
        result = self.validate_all(fail_fast=True)
        
        if not result.is_valid:
            error_msg = f"Configuration validation failed with {len(result.errors)} error(s)"
            logger.critical(error_msg)
            
            if app.config.get('ENVIRONMENT') == 'production':
                # Send alert to admins
                self._send_alert_to_admins(result.errors)
                raise RuntimeError(f"{error_msg}. Check logs for details.")
            else:
                logger.warning(f"Running in development despite configuration issues")
                return False
        
        return True
    
    def _send_alert_to_admins(self, errors: List[str]):
        """Send configuration error alerts to admins"""
        # Implementation would send email/SMS to admins
        # For now, just log it
        admin_emails = os.getenv('ADMIN_EMAILS', '').split(',')
        if admin_emails:
            logger.critical(f"Configuration errors need attention by: {', '.join(admin_emails)}")
    
    @staticmethod
    def generate_secret_key(length: int = 64) -> str:
        """Generate a cryptographically secure secret key"""
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @staticmethod
    def export_safe_config() -> Dict[str, Any]:
        """
        Export configuration with sensitive values masked.
        Useful for debugging without exposing secrets.
        """
        safe_config = {}
        
        for key, value in os.environ.items():
            if any(sensitive in key.lower() for sensitive in ['key', 'secret', 'password', 'token', 'auth']):
                if value:
                    safe_config[key] = f"***{value[-4:]}" if len(value) > 4 else "***"
            else:
                safe_config[key] = value
        
        return safe_config


def validate_configuration(app) -> bool:
    """Convenience function for easy integration"""
    validator = ConfigValidator(app)
    return validator.validate_configuration(app)


# Command-line interface for validation
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Validate application configuration")
    parser.add_argument("--env-file", help="Path to .env file to load")
    parser.add_argument("--generate-secret", action="store_true", 
                       help="Generate a secure secret key")
    parser.add_argument("--export-safe", action="store_true",
                       help="Export configuration with secrets masked")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Load environment file if specified
    if args.env_file:
        from dotenv import load_dotenv
        load_dotenv(args.env_file)
        logger.info(f"Loaded environment from {args.env_file}")
    
    # Generate secret key if requested
    if args.generate_secret:
        secret = ConfigValidator.generate_secret_key()
        print(f"\nGenerated secret key: {secret}")
        print(f"Length: {len(secret)} characters")
        sys.exit(0)
    
    # Export safe config if requested
    if args.export_safe:
        safe_config = ConfigValidator.export_safe_config()
        print(json.dumps(safe_config, indent=2))
        sys.exit(0)
    
    # Run validation
    validator = ConfigValidator()
    result = validator.validate_all(fail_fast=False)
    
    # Exit with appropriate code
    sys.exit(0 if result.is_valid else 1)
