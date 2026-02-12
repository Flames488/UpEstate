# app/services/automation_service.py - UPDATE EXISTING FILE

from app.domain.subscriptions import get_plan, can_create_automation, feature_enabled
from app.services.subscription_service import ensure_active_subscription

def create_automation_service(user, automation_count: int):
    """Service orchestrates - doesn't decide business logic"""
    
    # Check subscription status first
    ensure_active_subscription(user_id=user.id, tenant_id=tenant.id)
    
    # Domain decides
    plan = get_plan(user.plan)
    
    # Domain logic for limits
    if not can_create_automation(plan, automation_count):
        raise Forbidden(f"Plan limit reached. Maximum: {plan.max_automations}")
    
    # Domain logic for features
    if not feature_enabled(plan, "allow_ai_scoring"):
        raise Forbidden("AI scoring not available in your plan")
    
    # Service orchestrates (calls DB, external APIs, etc.)
    automation = create_automation_in_db(user.id)
    trigger_ai_scoring(automation.id)
    send_notification(user, "automation_created")
    
    return automation