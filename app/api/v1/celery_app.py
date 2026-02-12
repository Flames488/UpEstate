from celery import Celery
import os

def make_celery(app_name):
    return Celery(
        app_name,
        broker=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        backend=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        include=["app.automation.tasks"]
    )

celery = make_celery("automation_worker")
