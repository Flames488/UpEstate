from app.extensions import db
from .automation_states import AutomationState
from .retry_policy import retry

def execute_job(job, task_function):
    if job.state in [AutomationState.RUNNING, AutomationState.COMPLETED]:
        return

    job.state = AutomationState.RUNNING
    db.session.commit()

    try:
        retry(lambda: task_function(job))
        job.state = AutomationState.COMPLETED
        job.last_error = None
    except Exception as e:
        job.state = AutomationState.FAILED
        job.last_error = str(e)
        job.attempts += 1

    db.session.commit()