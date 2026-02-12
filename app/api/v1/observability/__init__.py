from app.config.settings import IS_MVP

def init_observability(app):
    if IS_MVP:
        # Minimal logging only
        app.logger.info("Observability disabled (MVP mode)")
        return

    # Existing advanced observability setup here
