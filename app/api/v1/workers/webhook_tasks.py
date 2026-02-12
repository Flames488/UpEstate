from celery import shared_task
from app.extensions import db
from app.services.stripe.handlers import handle_stripe_event

@shared_task(
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=30,
    retry_kwargs={"max_retries": 5},
    retry_jitter=True,
)
def process_stripe_event(self, event):
    try:
        handle_stripe_event(event)
    except Exception as exc:
        db.session.rollback()
        raise exc
