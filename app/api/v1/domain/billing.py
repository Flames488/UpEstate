from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True)
class BillingStatus:
    is_active: bool
    is_frozen: bool
    grace_period_ends_at: datetime | None


def can_charge(status: BillingStatus) -> bool:
    if not status.is_active:
        return False

    if status.is_frozen:
        return False

    if status.grace_period_ends_at and datetime.utcnow() > status.grace_period_ends_at:
        return False

    return True


def compute_grace_period(failure_count: int) -> timedelta:
    """Progressive grace period escalation"""
    if failure_count == 1:
        return timedelta(days=3)
    if failure_count == 2:
        return timedelta(days=7)
    return timedelta(days=0)