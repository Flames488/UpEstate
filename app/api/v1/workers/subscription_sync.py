import stripe
from celery import shared_task
from app.config import settings
from app.models.subscription import Subscription
from app.extensions import db

stripe.api_key = settings.STRIPE_SECRET_KEY

@shared_task
def sync_subscriptions():
    subs = Subscription.query.all()

    for sub in subs:
        try:
            stripe_sub = stripe.Subscription.retrieve(sub.stripe_subscription_id)

            sub.status = stripe_sub.status
            sub.current_period_end = stripe_sub.current_period_end
            sub.cancel_at_period_end = stripe_sub.cancel_at_period_end

            db.session.add(sub)
        except Exception:
            continue

    db.session.commit()
