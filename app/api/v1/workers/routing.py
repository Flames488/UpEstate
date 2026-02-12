# workers/routing.py
TASK_ROUTES = {
    "app.tasks.send_email": {"queue": "critical"},
    "app.tasks.process_payment": {"queue": "critical"},
}
