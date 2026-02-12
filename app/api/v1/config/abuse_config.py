from datetime import timedelta


class AbuseConfig:
    """Centralized configuration for abuse detection system."""
    
    # Scoring thresholds
    MAX_ABUSE_SCORE = 10
    WARNING_THRESHOLD = 7
    
    # Lock durations
    LOCK_DURATIONS = {
        'first_offense': timedelta(hours=6),
        'second_offense': timedelta(hours=24),
        'third_offense': timedelta(days=7),
        'persistent': timedelta(days=30)
    }
    
    # Score decay
    DECAY_INTERVAL = timedelta(hours=24)
    DECAY_AMOUNT = 1
    
    # Monitoring
    ENABLE_LOGGING = True
    LOG_LEVEL = 'WARNING'
    NOTIFY_ADMIN_THRESHOLD = 8
    
    # Plan-based limits
    PLAN_LIMITS = {
        "free": {
            "max_automations": 10,
            "rate_limit": 100,  # requests per hour
            "concurrent": 1
        },
        "pro": {
            "max_automations": 100,
            "rate_limit": 1000,
            "concurrent": 5
        },
        "enterprise": {
            "max_automations": 1000,
            "rate_limit": 10000,
            "concurrent": 50
        }
    }