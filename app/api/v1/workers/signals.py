# workers/signals.py
from celery.signals import task_failure
from workers.celery_app import celery_app

@task_failure.connect
def route_failed_tasks(sender=None, task_id=None, **kwargs):
    celery_app.send_task(
        sender.name,
        task_id=task_id,
        queue="dead_letter"
    )
