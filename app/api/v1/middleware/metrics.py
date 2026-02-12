
from app.config.settings import IS_MVP

def register_metrics(app):
    if IS_MVP:
        app.logger.info("Metrics disabled (MVP mode)")
        return

    # Existing metrics setup