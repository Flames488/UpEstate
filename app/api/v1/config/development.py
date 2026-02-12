from .base import BaseConfig


class DevelopmentConfig(BaseConfig):
    """
    Development configuration.
    """

    DEBUG = True

    SECRET_KEY = "dev-secret-key"

    SESSION_COOKIE_SECURE = False
