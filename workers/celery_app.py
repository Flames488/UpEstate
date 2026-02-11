import os
from celery import Celery

os.environ.setdefault("FLASK_CONFIG", "production")

celery = Celery(
    "realestate",
    broker=os.getenv("REDIS_URL"),
    backend=os.getenv("REDIS_URL"),
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)

def init_celery(app):
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        abstract = True

        def __call__(self, *args, **kwargs):
            with app.app_context():
                return super().__call__(*args, **kwargs)

    celery.Task = ContextTask
