# app/tasks/base.py
from celery import Task
from app.observability.tracing import tracer
from app.observability.metrics import task_executions_total
from app.observability.logging import get_logger

logger = get_logger(__name__)


class ObservedTask(Task):
    abstract = True

    def __call__(self, *args, **kwargs):
        task_name = self.name
        with tracer.start_as_current_span(
            "celery_task",
            attributes={"task.name": task_name},
        ):
            try:
                result = super().__call__(*args, **kwargs)
                task_executions_total.labels(
                    task_name=task_name, status="success"
                ).inc()
                return result
            except Exception:
                task_executions_total.labels(
                    task_name=task_name, status="failure"
                ).inc()
                logger.exception("Task failed", extra={"task": task_name})
                raise
