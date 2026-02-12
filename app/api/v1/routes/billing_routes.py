from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import os
import stripe
from app.services.stripe_service import (
    create_customer,
    create_subscription,
    cancel_subscription,
    get_subscription,
    update_subscription,
    create_payment_intent,
    create_checkout_session,
    get_customer,
    list_customer_subscriptions
)
from app.models.user import User
from app.extensions import db

bp = Blueprint("billing", __name__, url_prefix="/api/billing")


@bp.route("/create-customer", methods=["POST"])
@jwt_required()
def create_stripe_customer():
    """Create a Stripe customer for the current user"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"message": "User not found"}), 404
        
        # Check if user already has a Stripe customer ID
        if user.stripe_customer_id:
            return jsonify({
                "message": "Customer already exists",
                "customer_id": user.stripe_customer_id
            }), 200
        
        # Create Stripe customer
        customer = create_customer(
            email=user.email,
            name=user.full_name,
            metadata={"user_id": user.id}
        )
        
        # Save customer ID to user record
        user.stripe_customer_id = customer.id
        db.session.commit()
        
        return jsonify({
            "message": "Customer created successfully",
            "customer_id": customer.id
        }), 201
        
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500


@bp.route("/subscribe", methods=["POST"])
@jwt_required()
def subscribe():
    """Create a subscription for a customer"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"message": "User not found"}), 404
        
        data = request.json
        
        # Validate required fields
        if not data.get("price_id"):
            return jsonify({"message": "price_id is required"}), 400
        
        # Ensure user has a Stripe customer ID
        if not user.stripe_customer_id:
            return jsonify({"message": "User has no Stripe customer ID"}), 400
        
        # Optional trial period
        trial_period_days = data.get("trial_period_days")
        
        # Create subscription
        subscription = create_subscription(
            customer_id=user.stripe_customer_id,
            price_id=data["price_id"],
            trial_period_days=trial_period_days
        )
        
        # Update user subscription info
        user.subscription_id = subscription.id
        user.subscription_status = subscription.status
        user.subscription_plan = data.get("plan_name", "basic")  # Extract plan name from metadata
        db.session.commit()
        
        return jsonify({
            "message": "Subscription created successfully",
            "subscription_id": subscription.id,
            "status": subscription.status,
            "current_period_end": subscription.current_period_end
        }), 201
        
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500


@bp.route("/cancel-subscription", methods=["POST"])
@jwt_required()
def cancel_user_subscription():
    """Cancel a subscription"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.subscription_id:
            return jsonify({"message": "No active subscription found"}), 404
        
        subscription = cancel_subscription(user.subscription_id)
        
        # Update user subscription info
        user.subscription_status = subscription.status
        user.subscription_plan = None
        db.session.commit()
        
        return jsonify({
            "message": "Subscription cancelled successfully",
            "subscription_id": subscription.id,
            "status": subscription.status
        }), 200
        
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500


@bp.route("/subscription", methods=["GET"])
@jwt_required()
def get_subscription_details():
    """Get subscription details for current user"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.subscription_id:
            return jsonify({"message": "No subscription found"}), 404
        
        subscription = get_subscription(user.subscription_id)
        
        return jsonify({
            "subscription_id": subscription.id,
            "status": subscription.status,
            "current_period_start": subscription.current_period_start,
            "current_period_end": subscription.current_period_end,
            "cancel_at_period_end": subscription.cancel_at_period_end,
            "plan": {
                "id": subscription.plan.id,
                "amount": subscription.plan.amount,
                "currency": subscription.plan.currency,
                "interval": subscription.plan.interval
            }
        }), 200
        
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500


@bp.route("/update-subscription", methods=["PUT"])
@jwt_required()
def update_user_subscription():
    """Update subscription price/plan"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.subscription_id:
            return jsonify({"message": "No active subscription found"}), 404
        
        data = request.json
        
        if not data.get("price_id"):
            return jsonify({"message": "price_id is required"}), 400
        
        subscription = update_subscription(user.subscription_id, data["price_id"])
        
        # Update user subscription info
        user.subscription_status = subscription.status
        user.subscription_plan = data.get("plan_name", user.subscription_plan)
        db.session.commit()
        
        return jsonify({
            "message": "Subscription updated successfully",
            "subscription_id": subscription.id,
            "status": subscription.status
        }), 200
        
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500


@bp.route("/create-checkout-session", methods=["POST"])
@jwt_required()
def create_checkout():
    """Create a Stripe Checkout session with user metadata"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"message": "User not found"}), 404
        
        data = request.json
        
        if not data.get("price_id"):
            return jsonify({"message": "price_id is required"}), 400
        
        if not data.get("plan_name"):
            return jsonify({"message": "plan_name is required"}), 400
        
        success_url = data.get("success_url", f"{request.host_url}dashboard?session_id={{CHECKOUT_SESSION_ID}}")
        cancel_url = data.get("cancel_url", f"{request.host_url}dashboard")
        
        # Create checkout session with metadata
        session = create_checkout_session(
            price_id=data["price_id"],
            success_url=success_url,
            cancel_url=cancel_url,
            customer_email=user.email,
            metadata={
                "user_id": str(user.id),
                "plan_name": data["plan_name"]
            }
        )
        
        return jsonify({
            "session_id": session.id,
            "url": session.url,
            "message": "Checkout session created successfully"
        }), 201
        
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500


@bp.route("/customer/subscriptions", methods=["GET"])
@jwt_required()
def get_customer_subscriptions():
    """List all subscriptions for current user"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.stripe_customer_id:
            return jsonify({"subscriptions": [], "total": 0}), 200
        
        subscriptions = list_customer_subscriptions(user.stripe_customer_id)
        
        subscriptions_data = [{
            "subscription_id": sub.id,
            "status": sub.status,
            "current_period_end": sub.current_period_end,
            "plan": {
                "amount": sub.plan.amount,
                "currency": sub.plan.currency,
                "interval": sub.plan.interval
            }
        } for sub in subscriptions]
        
        return jsonify({
            "subscriptions": subscriptions_data,
            "total": len(subscriptions_data)
        }), 200
        
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500


@bp.route("/plans", methods=["GET"])
def get_plans():
    """Get available subscription plans"""
    try:
        # You can make this dynamic by fetching from Stripe
        # or define your plans statically
        plans = [
            {
                "id": "basic_monthly",
                "name": "Basic",
                "price_id": os.getenv("STRIPE_BASIC_PRICE_ID", "price_basic_monthly"),
                "amount": 29.99,
                "currency": "usd",
                "interval": "month",
                "features": ["100 leads/month", "Basic analytics", "Email support"]
            },
            {
                "id": "pro_monthly",
                "name": "Professional",
                "price_id": os.getenv("STRIPE_PRO_PRICE_ID", "price_pro_monthly"),
                "amount": 79.99,
                "currency": "usd",
                "interval": "month",
                "features": ["500 leads/month", "Advanced analytics", "Priority support", "API access"]
            },
            {
                "id": "enterprise_monthly",
                "name": "Enterprise",
                "price_id": os.getenv("STRIPE_ENTERPRISE_PRICE_ID", "price_enterprise_monthly"),
                "amount": 199.99,
                "currency": "usd",
                "interval": "month",
                "features": ["Unlimited leads", "Custom analytics", "24/7 support", "Custom integrations"]
            }
        ]
        
        return jsonify({"plans": plans}), 200
        
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500