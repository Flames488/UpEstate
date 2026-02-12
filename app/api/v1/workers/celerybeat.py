from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    "sync-stripe-subscriptions-hourly": {
        "task": "app.workers.subscription_sync.sync_subscriptions",
        "schedule": crontab(minute=0, hour="*/1"),
    },
}
