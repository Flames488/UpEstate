import os
from typing import Optional, ClassVar, Final
from functools import cached_property
import logging


class Settings:
    """Application settings management class."""
    
    # App Configuration
    APP_MODE: Final[str] = os.getenv("APP_MODE", "development").lower()
    IS_DEVELOPMENT: ClassVar[bool] = APP_MODE == "development"
    IS_PRODUCTION: ClassVar[bool] = APP_MODE == "production"
    IS_STAGING: ClassVar[bool] = APP_MODE == "staging"
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY")
    JWT_SECRET: str = os.getenv("JWT_SECRET")
    
    # Payment Integration
    PAYSTACK_SECRET_KEY: Optional[str] = os.getenv("PAYSTACK_SECRET_KEY")
    PAYSTACK_PUBLIC_KEY: Optional[str] = os.getenv("PAYSTACK_PUBLIC_KEY")
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///app.db")
    
    # Billing Providers
    STRIPE_ENABLED: ClassVar[bool] = False
    PAYSTACK_ENABLED: ClassVar[bool] = True
    PRIMARY_BILLING_PROVIDER: ClassVar[str] = "paystack"
    
    def __init__(self) -> None:
        """Validate critical settings on initialization."""
        self._validate_settings()
    
    @cached_property
    def DEBUG(self) -> bool:
        """Determine if debug mode is enabled."""
        return not self.IS_PRODUCTION
    
    @cached_property
    def LOG_LEVEL(self) -> int:
        """Get appropriate log level based on environment."""
        if self.IS_PRODUCTION:
            return logging.INFO
        return logging.DEBUG
    
    def _validate_settings(self) -> None:
        """Validate that required settings are present."""
        if self.IS_PRODUCTION:
            if not self.SECRET_KEY or self.SECRET_KEY == "dev-secret":
                raise ValueError(
                    "SECRET_KEY must be set and secure in production mode"
                )
            
            if not self.JWT_SECRET or self.JWT_SECRET == "jwt-secret":
                raise ValueError(
                    "JWT_SECRET must be set and secure in production mode"
                )
        
        if self.PAYSTACK_ENABLED and not self.PAYSTACK_SECRET_KEY:
            raise ValueError(
                "PAYSTACK_SECRET_KEY is required when PAYSTACK_ENABLED is True"
            )
    
    @property
    def is_testing(self) -> bool:
        """Check if application is in testing mode."""
        return self.APP_MODE == "testing"
    
    @property
    def database_url(self) -> str:
        """Get database URL with appropriate driver for environment."""
        if self.IS_PRODUCTION and "sqlite" in self.DATABASE_URL.lower():
            raise ValueError("SQLite is not suitable for production")
        return self.DATABASE_URL
    
    def __repr__(self) -> str:
        """Safe string representation hiding sensitive data."""
        return f"<Settings APP_MODE={self.APP_MODE}>"


# Singleton instance
settings = Settings()