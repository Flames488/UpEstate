from .base import BaseConfig


class ProductionConfig(BaseConfig):
    """
    Production configuration.
    """

    DEBUG = False

    # MUST be set via environment variable in real production
    SECRET_KEY = None

    SESSION_COOKIE_SECURE = True
