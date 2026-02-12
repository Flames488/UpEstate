def handle_stripe_event(event):
    event_type = event["type"]

    if event_type == "customer.subscription.created":
        handle_subscription_created(event)
    elif event_type == "customer.subscription.updated":
        handle_subscription_updated(event)
    elif event_type == "customer.subscription.deleted":
        handle_subscription_deleted(event)
    else:
        pass  # Ignore safely
