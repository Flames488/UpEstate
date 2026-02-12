# app/tasks/example_task.py
from workers.celery_app import celery_app
from workers.base_task import BaseTask

@celery_app.task(
    bind=True,
    base=BaseTask,
    name="app.tasks.example_task"
)
def example_task(self, user_id: int):
    # Safe, retryable, idempotent
    print(f"Processing user {user_id}")
