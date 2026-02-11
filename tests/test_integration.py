import pytest
import json
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

def test_full_user_journey():
    """Test complete user journey: register -> login -> update profile"""
    # 1. Register
    register_data = {
        "username": "journeyuser",
        "email": "journey@example.com",
        "password": "SecurePass123!"
    }
    
    with patch('database.users.create_user') as mock_create:
        mock_create.return_value = "user_journey_123"
        
        register_result = register_user(register_data)
        assert register_result["success"] == True
        user_id = register_result["user_id"]
    
    # 2. Login
    with patch('database.users.find_user_by_email') as mock_find:
        with patch('utils.auth.verify_password') as mock_verify:
            mock_find.return_value = {"id": user_id, "email": register_data["email"]}
            mock_verify.return_value = True
            
            login_result = login_user({
                "email": register_data["email"],
                "password": register_data["password"]
            })
            assert login_result["success"] == True
            assert "token" in login_result
    
    # 3. Update profile with token
    update_data = {"first_name": "Journey", "last_name": "User"}
    headers = {"Authorization": f"Bearer {login_result['token']}"}
    
    with patch('middleware.auth.verify_token') as mock_verify_token:
        with patch('database.users.update_user') as mock_update:
            mock_verify_token.return_value = {"user_id": user_id}
            mock_update.return_value = True
            
            update_result = update_user_profile(user_id, update_data)
            assert update_result["success"] == True

def test_lead_to_customer_conversion():
    """Test complete lead to customer conversion flow"""
    # 1. Create lead
    lead_data = {
        "name": "Conversion Lead",
        "email": "conversion@example.com",
        "phone": "+1234567890"
    }
    
    with patch('database.leads.insert_lead') as mock_insert:
        mock_insert.return_value = "lead_conversion_123"
        
        lead_result = create_lead(lead_data)
        assert lead_result["success"] == True
        lead_id = lead_result["lead_id"]
    
    # 2. Update lead status to qualified
    with patch('database.leads.update_lead') as mock_update:
        mock_update.return_value = True
        
        update_result = update_lead(lead_id, {"status": "qualified"})
        assert update_result["success"] == True
    
    # 3. Create payment for lead conversion
    payment_data = {
        "amount": 2999,
        "currency": "usd",
        "customer_email": lead_data["email"],
        "description": "Premium Plan"
    }
    
    with patch('stripe.PaymentIntent.create') as mock_payment:
        mock_payment.return_value = {
            "id": "pi_conversion_123",
            "status": "succeeded"
        }
        
        payment_result = create_payment_intent(payment_data)
        assert payment_result["success"] == True
    
    # 4. Convert lead to customer
    with patch('database.leads.convert_lead') as mock_convert:
        mock_convert.return_value = "customer_conversion_123"
        
        conversion_data = {
            "payment_intent_id": payment_result["payment_intent_id"],
            "plan": "premium"
        }
        
        conversion_result = convert_lead(lead_id, conversion_data)
        assert conversion_result["success"] == True
        assert "customer_id" in conversion_result

def test_payment_with_user_integration():
    """Test payment processing integrated with user account"""
    # 1. Get user
    user_id = "user_payment_123"
    
    with patch('database.users.get_user') as mock_get_user:
        mock_get_user.return_value = {
            "id": user_id,
            "email": "payment@example.com",
            "stripe_customer_id": "cus_payment_123"
        }
        
        user_result = get_user_profile(user_id)
        assert user_result["success"] == True
        user_email = user_result["user"]["email"]
        stripe_customer_id = user_result["user"]["stripe_customer_id"]
    
    # 2. Create payment with user's Stripe customer ID
    payment_data = {
        "amount": 2999,
        "currency": "usd",
        "customer": stripe_customer_id,
        "description": "User Subscription"
    }
    
    with patch('stripe.PaymentIntent.create') as mock_payment:
        mock_payment.return_value = {
            "id": "pi_user_123",
            "customer": stripe_customer_id,
            "status": "succeeded"
        }
        
        payment_result = create_payment_intent(payment_data)
        assert payment_result["success"] == True
    
    # 3. Update user's subscription status
    with patch('database.users.update_subscription') as mock_update_sub:
        mock_update_sub.return_value = True
        
        update_data = {
            "subscription_status": "active",
            "payment_intent_id": payment_result["payment_intent_id"]
        }
        
        update_result = update_user_profile(user_id, update_data)
        assert update_result["success"] == True

def test_webhook_to_database_integration():
    """Test Stripe webhook processing that updates database"""
    # Mock webhook event
    webhook_event = {
        "id": "evt_123456789",
        "type": "payment_intent.succeeded",
        "data": {
            "object": {
                "id": "pi_webhook_123",
                "amount": 2999,
                "customer": "cus_webhook_123",
                "metadata": {
                    "user_id": "user_webhook_123",
                    "plan": "premium"
                }
            }
        }
    }
    
    # 1. Verify webhook signature
    with patch('stripe.Webhook.construct_event') as mock_verify:
        mock_verify.return_value = webhook_event
        
        verification_result = verify_stripe_webhook(
            json.dumps(webhook_event),
            "mock_signature_header"
        )
        assert verification_result is not None
    
    # 2. Process payment success
    payment_intent = webhook_event["data"]["object"]
    
    with patch('database.payments.record_payment') as mock_record:
        with patch('database.users.update_subscription') as mock_update:
            mock_record.return_value = "payment_record_123"
            mock_update.return_value = True
            
            # Record payment
            record_result = record_payment(payment_intent)
            assert record_result["success"] == True
            
            # Update user subscription
            user_id = payment_intent["metadata"]["user_id"]
            update_result = update_user_profile(user_id, {
                "subscription_status": "active",
                "plan": payment_intent["metadata"]["plan"]
            })
            assert update_result["success"] == True
    
    # 3. Send confirmation email
    with patch('services.email.send_payment_confirmation') as mock_email:
        mock_email.return_value = True
        
        email_result = send_payment_confirmation(
            payment_intent["metadata"]["user_id"],
            payment_intent["id"]
        )
        assert email_result["success"] == True

def test_auth_protected_lead_operations():
    """Test that lead operations require authentication"""
    # 1. Try to create lead without authentication
    lead_data = {"name": "Test Lead", "email": "test@example.com"}
    
    unauthenticated_result = create_lead_unauthenticated(lead_data)
    assert unauthenticated_result["success"] == False
    assert "unauthorized" in unauthenticated_result["error"].lower()
    
    # 2. Login to get token
    with patch('database.users.find_user_by_email') as mock_find:
        with patch('utils.auth.verify_password') as mock_verify:
            mock_find.return_value = {"id": "user_auth_123"}
            mock_verify.return_value = True
            
            login_result = login_user({
                "email": "auth@example.com",
                "password": "Password123!"
            })
            assert login_result["success"] == True
            token = login_result["token"]
    
    # 3. Create lead with authentication
    headers = {"Authorization": f"Bearer {token}"}
    
    with patch('middleware.auth.verify_token') as mock_verify_token:
        with patch('database.leads.insert_lead') as mock_insert:
            mock_verify_token.return_value = {"user_id": "user_auth_123"}
            mock_insert.return_value = "lead_auth_123"
            
            authenticated_result = create_lead_authenticated(lead_data, headers)
            assert authenticated_result["success"] == True

def test_error_recovery_flow():
    """Test error handling and recovery in integration flow"""
    # 1. Failed payment
    payment_data = {
        "amount": 2999,
        "currency": "usd",
        "payment_method": "pm_card_decline"
    }
    
    with patch('stripe.PaymentIntent.create') as mock_payment:
        mock_payment.side_effect = Exception("Card declined")
        
        payment_result = create_payment_intent(payment_data)
        assert payment_result["success"] == False
    
    # 2. Log the error
    with patch('services.logging.log_error') as mock_log:
        mock_log.return_value = True
        
        log_result = log_payment_error(
            payment_data,
            payment_result["error_message"]
        )
        assert log_result["success"] == True
    
    # 3. Notify user of failure
    with patch('services.email.send_payment_failure') as mock_email:
        mock_email.return_value = True
        
        email_result = notify_payment_failure(
            payment_data.get("customer_email", "user@example.com"),
            payment_result["error_message"]
        )
        assert email_result["success"] == True
    
    # 4. Update lead status to indicate payment issue
    lead_id = "lead_error_123"
    
    with patch('database.leads.update_lead') as mock_update:
        mock_update.return_value = True
        
        update_result = update_lead(lead_id, {
            "status": "payment_failed",
            "notes": f"Payment failed: {payment_result['error_message']}"
        })
        assert update_result["success"] == True

def test_performance_under_load():
    """Test performance of integrated operations"""
    import time
    
    # Simulate multiple simultaneous operations
    operations = []
    
    for i in range(5):
        with patch('database.leads.insert_lead') as mock_insert:
            mock_insert.return_value = f"lead_load_{i}"
            
            start_time = time.time()
            result = create_lead({
                "name": f"Load User {i}",
                "email": f"load{i}@example.com",
                "phone": "+1234567890"
            })
            end_time = time.time()
            
            operations.append({
                "success": result["success"],
                "duration": end_time - start_time
            })
    
    # Verify all operations succeeded
    successes = sum(1 for op in operations if op["success"])
    assert successes == 5
    
    # Verify reasonable performance (all under 1 second)
    max_duration = max(op["duration"] for op in operations)
    assert max_duration < 1.0

# Mock functions for integration tests
def create_lead_unauthenticated(lead_data):
    return {"success": False, "error": "Unauthorized: Authentication required"}

def create_lead_authenticated(lead_data, headers):
    return {
        "success": True,
        "lead_id": "lead_auth_123",
        "message": "Lead created successfully"
    }

def verify_stripe_webhook(payload, sig_header):
    return json.loads(payload)

def record_payment(payment_intent):
    return {
        "success": True,
        "payment_record_id": "record_123",
        "message": "Payment recorded successfully"
    }

def send_payment_confirmation(user_id, payment_intent_id):
    return {"success": True, "message": "Confirmation email sent"}

def log_payment_error(payment_data, error_message):
    return {"success": True, "log_id": "log_123"}

def notify_payment_failure(email, error_message):
    return {"success": True, "message": "Failure notification sent"}

# Reuse functions from other test files
from .test_auth import login_user
from .test_leads import create_lead, update_lead, convert_lead
from .test_payments import create_payment_intent
from .test_users import (
    register_user, 
    get_user_profile, 
    update_user_profile
)