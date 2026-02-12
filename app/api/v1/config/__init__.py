import os

from .base import ConfigurationError
from .development import DevelopmentConfig
from .production import ProductionConfig


def get_config():
    """
    Resolve and return the correct configuration class
    based on the APP_ENV environment variable.

    Supported values:
    - development
    - production
    """

    env = os.getenv("APP_ENV", "development").lower()

    if env == "development":
        return DevelopmentConfig

    if env == "production":
        return ProductionConfig

    raise ConfigurationError(f"Invalid APP_ENV value: {env}")
