import logging.config
import sys

# Define logging configuration FIRST
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,

    "formatters": {
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
            # Additional recommended JSON formatter options
            "json_ensure_ascii": False,
            "json_indent": None,
        },
        "console": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        }
    },

    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",  # Change to "console" for non-JSON output
            "stream": sys.stdout,
        },
        "error_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "json",
            "filename": "error.log",
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5,
            "level": "ERROR",
        }
    },

    "loggers": {
        # Application-specific logger
        "myapp": {
            "handlers": ["console", "error_file"],
            "level": "INFO",
            "propagate": False,
        }
    },

    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
}

def configure_logging(config=None):
    """
    Configure logging for the application.
    
    Args:
        config (dict, optional): Custom logging configuration.
        Uses default LOGGING_CONFIG if not provided.
    """
    try:
        if config is None:
            config = LOGGING_CONFIG
        
        logging.config.dictConfig(config)
        
        # Get a logger to confirm configuration
        logger = logging.getLogger(__name__)
        logger.info("Logging configured successfully")
        
        return logger
    except Exception as e:
        # Fallback basic configuration if dictConfig fails
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        logging.error(f"Failed to configure logging: {e}")
        raise

# Optional: Configure on module import if desired
# __all__ = ["configure_logging", "LOGGING_CONFIG"]