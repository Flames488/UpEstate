# workers/base_task.py
from celery import Task
from celery.utils.log import get_task_logger
from app.utils.idempotency import ensure_idempotent

logger = get_task_logger(__name__)

class BaseTask(Task):
    abstract = True

    autoretry_for = (Exception,)
    retry_kwargs = {"max_retries": 5}
    retry_backoff = True
    retry_backoff_max = 300
    retry_jitter = True

    def __call__(self, *args, **kwargs):
        task_id = self.request.id
        with ensure_idempotent(self.name, task_id):
            return super().__call__(*args, **kwargs)

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        logger.error(
            "Task failed",
            extra={
                "task": self.name,
                "task_id": task_id,
                "error": str(exc),
            }
        )
