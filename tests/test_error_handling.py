import pytest
import json
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
import stripe
from stripe.error import StripeError

# Advanced error handling tests
def test_stripe_error_handling_cascade():
    """Test cascade of Stripe error handling"""
    error_scenarios = [
        {
            "error": CardError(
                message="Card declined",
                param="card",
                code="card_declined",
                json_body={"error": {"code": "card_declined"}}
            ),
            "expected_action": "ask_for_new_card",
            "should_retry": False
        },
        {
            "error": StripeError(
                message="Rate limit exceeded",
                http_status=429
            ),
            "expected_action": "retry_with_backoff",
            "should_retry": True
        },
        {
            "error": StripeError(
                message="Invalid request",
                http_status=400
            ),
            "expected_action": "validate_input",
            "should_retry": False
        },
        {
            "error": ConnectionError("Network issue"),
            "expected_action": "retry_later",
            "should_retry": True
        }
    ]
    
    results = []
    for scenario in error_scenarios:
        result = handle_stripe_error(scenario["error"])
        results.append({
            "action": result["action"],
            "should_retry": result.get("should_retry", False),
            "matches_expected": result["action"] == scenario["expected_action"]
        })
    
    assert all(r["matches_expected"] for r in results)

def test_stripe_error_graceful_degradation():
    """Test graceful degradation when Stripe is unavailable"""
    with patch('stripe.Customer.create') as mock_create:
        mock_create.side_effect = StripeError(
            "Service unavailable",
            http_status=503
        )
        
        with patch('services.fallback.use_local_billing') as mock_fallback:
            mock_fallback.return_value = {"local_customer_id": "local_123"}
            
            result = create_customer_with_fallback({
                "email": "customer@example.com",
                "name": "John Doe"
            })
            
            assert result["success"] == True
            assert result["source"] == "local_fallback"
            assert "local_customer_id" in result

def test_stripe_error_recovery_retry():
    """Test error recovery with retry mechanism"""
    call_count = 0
    
    def failing_then_succeeding():
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise StripeError(f"Temporary failure {call_count}", http_status=500)
        return {"id": "cus_success_123"}
    
    with patch('stripe.Customer.create', side_effect=failing_then_succeeding):
        with patch('time.sleep') as mock_sleep:
            result = create_customer_with_retry({
                "email": "customer@example.com"
            }, max_retries=3)
            
            assert result["success"] == True
            assert call_count == 3
            assert mock_sleep.call_count == 2  # Slept before retries 2 and 3

def test_stripe_error_circuit_breaker():
    """Test circuit breaker pattern for Stripe errors"""
    with patch('stripe.PaymentIntent.create') as mock_create:
        mock_create.side_effect = StripeError(
            "Service unavailable",
            http_status=503
        )
        
        # Make multiple failing calls
        failures = 0
        for i in range(10):
            try:
                create_payment_intent({"amount": 1000})
            except Exception as e:
                failures += 1
        
        # After certain failures, circuit should open
        assert failures >= 5
        # Verify circuit breaker state
        circuit_state = get_circuit_breaker_state("stripe_payments")
        assert circuit_state["state"] in ["open", "half_open"]

def test_stripe_error_alerting():
    """Test error alerting system"""
    error = StripeError("Critical payment failure", http_status=402)
    
    with patch('services.monitoring.send_alert') as mock_alert:
        with patch('services.logging.log_critical') as mock_log:
            with patch('services.notification.notify_team') as mock_notify:
                mock_alert.return_value = True
                mock_log.return_value = True
                mock_notify.return_value = True
                
                result = handle_critical_stripe_error(error, "payment_processing")
                
                assert result["alerted"] == True
                assert mock_alert.call_count == 1
                assert mock_notify.call_count >= 1

def test_stripe_error_user_feedback():
    """Test user-friendly error messages"""
    stripe_errors = [
        {
            "error": CardError("Your card was declined", param="card", code="card_declined"),
            "expected_user_message": "Your card was declined. Please try a different card."
        },
        {
            "error": StripeError("Invalid email", http_status=400),
            "expected_user_message": "Please check your email address and try again."
        },
        {
            "error": StripeError("Rate limit exceeded", http_status=429),
            "expected_user_message": "Too many requests. Please try again in a few minutes."
        }
    ]
    
    for scenario in stripe_errors:
        user_message = get_user_friendly_error(scenario["error"])
        assert user_message == scenario["expected_user_message"]
        assert "Please" in user_message  # All user messages should be polite

# Mock functions for error handling
def handle_stripe_error(error):
    error_type = type(error).__name__
    
    if error_type == "CardError":
        error_code = getattr(error, 'code', None)
        
        if error_code == "card_declined":
            return {
                "action": "ask_for_new_card",
                "message": "Card was declined",
                "should_retry": False,
                "user_message": "Your card was declined. Please try a different payment method."
            }
        elif error_code == "insufficient_funds":
            return {
                "action": "suggest_alternative",
                "message": "Insufficient funds",
                "should_retry": False,
                "user_message": "Your card has insufficient funds. Please use a different card or contact your bank."
            }
    
    elif error_type == "StripeError":
        http_status = getattr(error, 'http_status', 0)
        
        if http_status == 429:  # Rate limit
            return {
                "action": "retry_with_backoff",
                "message": "Rate limit exceeded",
                "should_retry": True,
                "retry_after": 60
            }
        elif http_status >= 500:  # Server error
            return {
                "action": "retry_later",
                "message": "Service temporarily unavailable",
                "should_retry": True,
                "user_message": "We're experiencing technical difficulties. Please try again in a few minutes."
            }
    
    # Generic error handling
    return {
        "action": "log_and_notify",
        "message": str(error),
        "should_retry": False,
        "user_message": "An unexpected error occurred. Our team has been notified."
    }

def create_customer_with_fallback(customer_data):
    try:
        customer = stripe.Customer.create(**customer_data)
        return {
            "success": True,
            "source": "stripe",
            "customer_id": customer.id,
            "stripe_response": customer
        }
    except StripeError as e:
        # Fallback to local billing
        local_customer = create_local_customer(customer_data)
        return {
            "success": True,
            "source": "local_fallback",
            "local_customer_id": local_customer["id"],
            "fallback_reason": str(e)
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "source": "error"
        }

def create_customer_with_retry(customer_data, max_retries=3):
    retry_count = 0
    last_error = None
    
    while retry_count <= max_retries:
        try:
            customer = stripe.Customer.create(**customer_data)
            return {
                "success": True,
                "customer_id": customer.id,
                "retry_count": retry_count
            }
        except StripeError as e:
            last_error = e
            retry_count += 1
            
            if retry_count <= max_retries:
                # Exponential backoff
                sleep_time = 2 ** retry_count
                time.sleep(sleep_time)
    
    return {
        "success": False,
        "error": f"Failed after {max_retries} retries: {str(last_error)}",
        "retry_count": retry_count
    }

def get_user_friendly_error(error):
    error_type = type(error).__name__
    
    if error_type == "CardError":
        error_code = getattr(error, 'code', None)
        
        error_messages = {
            "card_declined": "Your card was declined. Please try a different card.",
            "expired_card": "Your card has expired. Please update your card details.",
            "insufficient_funds": "Your card has insufficient funds. Please use a different card or contact your bank.",
            "incorrect_cvc": "The security code is incorrect. Please check and try again.",
            "processing_error": "There was an error processing your card. Please try again."
        }
        
        return error_messages.get(error_code, "There was an issue with your card. Please try again.")
    
    elif error_type == "StripeError":
        http_status = getattr(error, 'http_status', 0)
        
        if http_status == 400:
            return "Please check your information and try again."
        elif http_status == 429:
            return "Too many requests. Please try again in a few minutes."
        elif http_status >= 500:
            return "We're experiencing technical difficulties. Please try again in a few minutes."
    
    # Default user-friendly message
    return "An unexpected error occurred. Please try again or contact support if the problem persists."