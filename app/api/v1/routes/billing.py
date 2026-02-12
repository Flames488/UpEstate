from flask import Blueprint, jsonify, abort
from services.stripe_service import create_checkout_session
from middleware.auth import jwt_required, current_user
from app.security.domain import billing_allowed, SystemState
from app.feature_flags import GLOBAL_FLAGS

billing_bp = Blueprint("billing", __name__)

# System configuration - could be moved to config module if used elsewhere
system_state = SystemState(
    billing_enabled=GLOBAL_FLAGS.enable_payments,
    automations_enabled=True,
    webhooks_enabled=True,
)


def validate_billing_enabled():
    """
    Validates if billing functionality is enabled in the system.
    Aborts with 503 Service Unavailable if billing is disabled.
    """
    if not billing_allowed(system_state):
        abort(503, "Billing temporarily disabled")


@billing_bp.route("/health", methods=["GET"])
def billing_health():
    """
    Health check endpoint for billing service.
    Returns system state information.
    """
    return jsonify({
        "service": "billing",
        "status": "operational" if billing_allowed(system_state) else "disabled",
        "billing_enabled": system_state.billing_enabled,
        "automations_enabled": system_state.automations_enabled,
        "webhooks_enabled": system_state.webhooks_enabled
    })


@billing_bp.route("/subscribe", methods=["POST"])
@jwt_required
def subscribe():
    """
    Creates a checkout session for user subscription.
    
    Returns:
        JSON response containing the checkout URL or error details.
        
    Raises:
        503: If billing functionality is disabled
        400: If user data is invalid
        500: If checkout session creation fails
    """
    try:
        # Validate billing is enabled
        validate_billing_enabled()
        
        # Validate required user data
        if not current_user.id or not current_user.email:
            abort(400, "User ID and email are required for subscription")
        
        # Create checkout session
        url = create_checkout_session(
            user_id=current_user.id,
            user_email=current_user.email
        )
        
        return jsonify({
            "status": "success",
            "checkout_url": url,
            "message": "Checkout session created successfully"
        })
        
    except Exception as e:
        # Log the error here (you would typically add logging)
        # logger.error(f"Subscription failed for user {current_user.id}: {str(e)}")
        
        # Re-raise abort exceptions
        if isinstance(e, (abort, type(abort))):
            raise
        
        # Handle other exceptions
        abort(500, f"Failed to create subscription: {str(e)}")


@billing_bp.route("/status", methods=["GET"])
@jwt_required
def billing_status():
    """
    Returns the current billing status for the authenticated user.
    Useful for frontend to determine if billing features should be shown.
    """
    return jsonify({
        "billing_available": billing_allowed(system_state),
        "user_id": current_user.id,
        "features": {
            "subscriptions": system_state.billing_enabled,
            "automations": system_state.automations_enabled,
            "webhooks": system_state.webhooks_enabled
        }
    })