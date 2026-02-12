from dataclasses import dataclass


@dataclass(frozen=True)
class Plan:
    name: str
    max_automations: int
    allow_ai_scoring: bool
    allow_webhooks: bool


PLANS = {
    "free": Plan("free", 1, False, False),
    "pro": Plan("pro", 10, True, True),
    "enterprise": Plan("enterprise", 1000, True, True),
}


def get_plan(plan_name: str) -> Plan:
    return PLANS.get(plan_name, PLANS["free"])


def can_create_automation(plan: Plan, current_count: int) -> bool:
    return current_count < plan.max_automations


def feature_enabled(plan: Plan, feature: str) -> bool:
    return getattr(plan, feature, False)