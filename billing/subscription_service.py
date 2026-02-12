
from app.billing.plans import PLANS

def assert_plan_allows(plan: str, action: str):
    if not PLANS.get(plan, {}).get(action, False):
        raise PermissionError("Upgrade required for this action")
