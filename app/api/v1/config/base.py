class ConfigurationError(Exception):
    """
    Raised when an invalid or unsupported configuration is requested.
    """
    pass


class BaseConfig:
    """
    Base configuration shared by all environments.
    """

    # Flask
    DEBUG = False
    TESTING = False
    SECRET_KEY = None

    # Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Application
    APP_NAME = "Real Estate Automation Enterprise"
