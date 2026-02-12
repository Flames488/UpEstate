import stripe
from datetime import datetime
from app.extensions import db
from app.config import settings
from app.models.stripe import SubscriptionState

stripe.api_key = settings.STRIPE_SECRET_KEY


def reconcile_subscriptions():
    subscriptions = SubscriptionState.query.all()

    for sub in subscriptions:
        try:
            stripe_sub = stripe.Subscription.retrieve(
                sub.stripe_subscription_id
            )

            sub.status = stripe_sub.status
            sub.current_period_end = datetime.fromtimestamp(
                stripe_sub.current_period_end
            )

            db.session.add(sub)
        except stripe.error.InvalidRequestError:
            sub.status = "canceled"
            db.session.add(sub)

    db.session.commit()
