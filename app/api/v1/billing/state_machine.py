from enum import Enum
from datetime import datetime
from sqlalchemy.exc import SQLAlchemyError

from app.db.session import db
from app.models.payment import Payment
from app.models.subscription import Subscription


class PaymentStatus(str, Enum):
    INITIATED = "initiated"
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SubscriptionStatus(str, Enum):
    INACTIVE = "inactive"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    CANCELLED = "cancelled"


class InvalidStateTransition(Exception):
    pass


class BillingStateMachine:
    """
    Authoritative billing state machine.

    This class is the ONLY place where:
    - Payments change state
    - Subscriptions become active
    - Entitlements are granted

    If it doesn't go through here, it doesn't happen.
    """

    @staticmethod
    def confirm_payment(
        *,
        payment_reference: str,
        provider: str = "paystack",
        metadata: dict | None = None
    ) -> Subscription:
        """
        Called ONLY after provider webhook verification succeeds.
        This method is idempotent and safe to call multiple times.
        """

        try:
            payment = (
                Payment.query
                .filter_by(reference=payment_reference, provider=provider)
                .with_for_update()
                .first()
            )

            if not payment:
                raise InvalidStateTransition(
                    f"Payment with reference {payment_reference} not found"
                )

            # Idempotency: already confirmed
            if payment.status == PaymentStatus.CONFIRMED:
                return BillingStateMachine._activate_subscription(payment)

            if payment.status in (
                PaymentStatus.FAILED,
                PaymentStatus.CANCELLED
            ):
                raise InvalidStateTransition(
                    f"Cannot confirm payment in status {payment.status}"
                )

            # Transition payment → CONFIRMED
            payment.status = PaymentStatus.CONFIRMED
            payment.confirmed_at = datetime.utcnow()
            payment.metadata = metadata or payment.metadata

            db.session.flush()

            # Payment confirmed → activate subscription
            subscription = BillingStateMachine._activate_subscription(payment)

            db.session.commit()
            return subscription

        except SQLAlchemyError:
            db.session.rollback()
            raise

    @staticmethod
    def _activate_subscription(payment: Payment) -> Subscription:
        """
        Internal method.
        Activates subscription ONLY if payment is confirmed.
        """

        if payment.status != PaymentStatus.CONFIRMED:
            raise InvalidStateTransition(
                "Subscription activation requires confirmed payment"
            )

        subscription = (
            Subscription.query
            .filter_by(id=payment.subscription_id)
            .with_for_update()
            .first()
        )

        if not subscription:
            raise InvalidStateTransition(
                "Subscription not found for payment"
            )

        # Idempotency: already active
        if subscription.status == SubscriptionStatus.ACTIVE:
            return subscription

        if subscription.status in (
            SubscriptionStatus.CANCELLED,
            SubscriptionStatus.SUSPENDED
        ):
            raise InvalidStateTransition(
                f"Cannot activate subscription in status {subscription.status}"
            )

        # Activate subscription
        subscription.status = SubscriptionStatus.ACTIVE
        subscription.activated_at = datetime.utcnow()
        subscription.last_payment_id = payment.id

        db.session.flush()

        return subscription

    @staticmethod
    def fail_payment(
        *,
        payment_reference: str,
        provider: str = "paystack",
        reason: str | None = None
    ) -> None:
        """
        Marks payment as failed.
        Does NOT activate subscription.
        """

        payment = (
            Payment.query
            .filter_by(reference=payment_reference, provider=provider)
            .with_for_update()
            .first()
        )

        if not payment:
            return

        if payment.status == PaymentStatus.CONFIRMED:
            # Confirmed payments cannot be failed retroactively
            return

        payment.status = PaymentStatus.FAILED
        payment.failure_reason = reason
        payment.failed_at = datetime.utcnow()

        db.session.commit()
