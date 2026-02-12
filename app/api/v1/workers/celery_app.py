# workers/celery_app.py
from celery import Celery
from kombu import Queue
from config.settings import settings
from app.tasks.base import ObservedTask

# Initialize Celery app with configuration from your config module
celery_app = Celery(
    "upestate",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["app.tasks"]
)

# Set custom task base class
celery_app.Task = ObservedTask

# Load configuration from your celery config file
celery_app.config_from_object("app.config.celery")

# Update configuration with additional settings
celery_app.conf.update(
    # Serialization
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    
    # Timezone
    timezone="UTC",
    enable_utc=True,
    
    # Reliability settings
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_reject_on_worker_lost=True,
    
    # Retry behavior
    task_default_retry_delay=5,
    task_max_retries=5,
    
    # Routing
    task_default_queue="default",
    task_queues=(
        Queue("default"),
        Queue("critical"),
        Queue("dead_letter"),
    ),
    
    # Time limits
    task_time_limit=300,
    task_soft_time_limit=240,
)

# Auto-discover tasks in the registered apps
celery_app.autodiscover_tasks()