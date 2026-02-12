def create_worker_context():
    from app.config.settings import settings
    from app.extensions import db
    return settings, db
