# app/routes/stripe_webhook.py
from fastapi import APIRouter, Request, Response, status, Depends
from fastapi.responses import JSONResponse
from datetime import datetime
from typing import Dict, Any
import json
import hashlib

# Import your FastAPI dependencies
from config.settings import settings
# Removed: from app.services.stripe.webhook_signature import verify_webhook_signature
# Removed: from app.services.stripe.webhook_idempotency import (
#     is_event_processed,
#     mark_event_processed,
#     EventProcessingStatus
# )
# Removed: from app.services.alerting import send_alert
from app.cache import redis_client
from app.monitoring.metrics import webhook_metrics
# Removed: from app.workers.webhook_tasks import process_stripe_event
# Removed: from models.user import User
# Removed: from database import db

router = APIRouter()

# ==================== STRIPE WEBHOOK KILL-SWITCH ====================
# Set this to True to completely disable Stripe webhook processing
# When disabled: All webhook requests return 410 (Gone) immediately
# All other endpoints (/health, /metrics, /replay) remain operational
# ====================================================================
STRIPE_WEBHOOKS_DISABLED = True  # 🚨 KILL-SWITCH: Set to True to disable
DISABLE_SINCE = "2024-01-01T00:00:00Z"  # Timestamp when disabled
DISABLE_REASON = "Maintenance: Preventing accidental subscription activation"
# ====================================================================

# Webhook event rate limiting
WEBHOOK_RATE_LIMIT_KEY = "stripe_webhook:rate_limit"
MAX_EVENTS_PER_MINUTE = 100


async def _verify_rate_limit() -> bool:
    """
    Implement rate limiting for webhook endpoint
    Returns True if within rate limit, False otherwise
    """
    import time
    current_minute = int(time.time() // 60)
    key = f"{WEBHOOK_RATE_LIMIT_KEY}:{current_minute}"
    
    try:
        count = await redis_client.incr(key)
        if count == 1:
            await redis_client.expire(key, 60)  # Expire after 1 minute
        
        if count > MAX_EVENTS_PER_MINUTE:
            webhook_metrics.increment("webhook_rate_limited")
            # Removed alert sending since send_alert is no longer imported
            return False
        return True
    except Exception as e:
        # Log error but fail open
        return True


@router.post("/webhook")
async def stripe_webhook_disabled(request: Request):
    """
    Stripe webhook endpoint with kill-switch capability
    Returns 410 Gone when disabled to stop Stripe retries
    """
    
    # 🚨 KILL-SWITCH CHECK: Immediate 410 response if disabled
    if STRIPE_WEBHOOKS_DISABLED:
        # Log the attempt for audit purposes
        event_id = "unknown"
        user_agent = request.headers.get("user-agent", "unknown")
        client_host = request.client.host if request.client else "unknown"
        
        try:
            body = await request.body()
            if body:
                data = json.loads(body.decode('utf-8'))
                event_id = data.get('id', 'unknown')
        except:
            pass
            
        # Log warning
        print(f"WARNING: Stripe webhook disabled - rejecting request from {client_host}. "
              f"Event ID: {event_id}, User-Agent: {user_agent}")
        
        # Return 410 Gone with explanation
        return JSONResponse(
            status_code=status.HTTP_410_GONE,
            content={
                "status": "disabled",
                "message": "Stripe webhook processing is permanently disabled",
                "disabled_since": DISABLE_SINCE,
                "reason": DISABLE_REASON,
                "re_enable_instruction": "Set STRIPE_WEBHOOKS_DISABLED = False in stripe_webhook.py",
                "timestamp": datetime.utcnow().isoformat()
            }
        )
    
    # If webhooks are enabled, continue with normal processing
    # This is your existing webhook logic (adapted for FastAPI)
    return await process_stripe_webhook(request)


async def process_stripe_webhook(request: Request):
    """
    Process Stripe webhook when enabled
    Note: This is kept for completeness but won't be used when STRIPE_WEBHOOKS_DISABLED = True
    """
    start_time = datetime.utcnow()
    request_id = request.headers.get('X-Request-ID') or hashlib.md5(str(start_time.timestamp()).encode()).hexdigest()
    
    try:
        # Check rate limit
        if not await _verify_rate_limit():
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "retry_after": 60
                }
            )
        
        # Get request data
        body = await request.body()
        sig_header = request.headers.get("Stripe-Signature")
        
        # Since Stripe is deprecated, this would only process if re-enabled
        # For now, return a maintenance message
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "stripe_disabled",
                "message": "Stripe functionality is deprecated and disabled",
                "request_id": request_id,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Internal server error",
                "request_id": request_id
            }
        )


@router.get("/health")
async def webhook_health():
    """
    Health check endpoint for webhook service
    Shows current kill-switch status
    """
    redis_status = False
    if redis_client:
        try:
            redis_status = await redis_client.ping()
        except:
            redis_status = False
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "stripe_webhook",
        "webhooks_enabled": not STRIPE_WEBHOOKS_DISABLED,
        "disabled_since": DISABLE_SINCE if STRIPE_WEBHOOKS_DISABLED else None,
        "disable_reason": DISABLE_REASON if STRIPE_WEBHOOKS_DISABLED else None,
        "checks": {
            "redis": redis_status,
            "kill_switch_active": STRIPE_WEBHOOKS_DISABLED,
            "stripe_deprecated": True
        }
    }


@router.get("/kill-switch/status")
async def kill_switch_status():
    """
    Endpoint to check current kill-switch status
    Useful for monitoring and automation
    """
    return {
        "enabled": STRIPE_WEBHOOKS_DISABLED,
        "disabled_since": DISABLE_SINCE,
        "reason": DISABLE_REASON,
        "webhook_endpoint": "410 Gone" if STRIPE_WEBHOOKS_DISABLED else "503 Service Unavailable",
        "re_enable_instruction": "Set STRIPE_WEBHOOKS_DISABLED = False in stripe_webhook.py AND update StripeEvent model",
        "timestamp": datetime.utcnow().isoformat(),
        "note": "Stripe functionality is deprecated. Re-enabling requires model updates."
    }


# Removed: @router.post("/test/{event_type}") - Test endpoint removed since Stripe is deprecated