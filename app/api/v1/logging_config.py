# app/logging_config.py
import logging
import logging.config
import os
from datetime import datetime
from flask import g, request
from pythonjsonlogger import jsonlogger


class RequestIdFilter(logging.Filter):
    """
    Inject request_id into every log record if present.
    """

    def filter(self, record):
        record.request_id = getattr(g, "request_id", None)
        return True


def setup_logging(app):
    """Configure logging for the application"""
    # Configure structured JSON logging
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    
    # Set log level based on app config if provided, otherwise use environment variable
    app_log_level = app.config.get('LOG_LEVEL', log_level).upper()
    
    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "filters": {
            "request_id": {
                "()": RequestIdFilter,
            },
        },
        "formatters": {
            "json": {
                "()": jsonlogger.JsonFormatter,
                "fmt": (
                    "%(asctime)s "
                    "%(levelname)s "
                    "%(name)s "
                    "%(message)s "
                    "%(request_id)s "
                    "%(module)s "
                    "%(funcName)s "
                    "%(lineno)d"
                ),
            },
            "simple": {
                "format": '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            },
        },
        "handlers": {
            "default": {
                "class": "logging.StreamHandler",
                "formatter": "json",
                "filters": ["request_id"],
            },
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "simple",
                "level": "DEBUG" if app_log_level == "DEBUG" else "INFO",
            },
        },
        "root": {
            "level": app_log_level,
            "handlers": ["default"],  # Always use JSON logging as default
        },
    }
    
    # Apply the logging configuration
    logging.config.dictConfig(logging_config)
    
    # Set Flask app logger
    logger = logging.getLogger(__name__)
    app.logger = logger
    
    # Request logging middleware
    @app.before_request
    def log_request():
        log_requests = app.config.get('LOG_REQUESTS', False)
        debug_mode = app.config.get('DEBUG', False)
        
        if debug_mode or log_requests:
            g.start_time = datetime.now()
            request_id = getattr(g, "request_id", "N/A")
            app.logger.info(
                f"Request: {request.method} {request.path}",
                extra={
                    "ip": request.remote_addr,
                    "user_agent": request.user_agent.string if request.user_agent else None,
                    "request_id": request_id
                }
            )
    
    @app.after_request
    def log_response(response):
        log_requests = app.config.get('LOG_REQUESTS', False)
        debug_mode = app.config.get('DEBUG', False)
        
        if (debug_mode or log_requests) and hasattr(g, 'start_time'):
            duration = (datetime.now() - g.start_time).total_seconds() * 1000
            request_id = getattr(g, "request_id", "N/A")
            app.logger.info(
                f"Response: {request.method} {request.path} - {response.status_code}",
                extra={
                    "status_code": response.status_code,
                    "duration_ms": round(duration, 2),
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.path
                }
            )
        return response
    
    return app


# Optional: Helper function for non-Flask applications
def configure_logging_for_non_flask():
    """Configure logging for non-Flask applications (standalone scripts, etc.)"""
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    
    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {
                "()": jsonlogger.JsonFormatter,
                "fmt": (
                    "%(asctime)s "
                    "%(levelname)s "
                    "%(name)s "
                    "%(message)s "
                    "%(module)s "
                    "%(funcName)s "
                    "%(lineno)d"
                ),
            },
        },
        "handlers": {
            "default": {
                "class": "logging.StreamHandler",
                "formatter": "json",
            },
        },
        "root": {
            "level": log_level,
            "handlers": ["default"],
        },
    }
    
    logging.config.dictConfig(logging_config)