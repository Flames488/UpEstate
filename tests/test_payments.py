import pytest
import json
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
import stripe
from stripe.error import CardError, StripeError

def test_create_payment_intent_success(mock_payment_data, mock_stripe_payment_intent):
    """Test successful payment intent creation"""
    with patch('stripe.PaymentIntent.create') as mock_create:
        mock_create.return_value = mock_stripe_payment_intent
        
        result = create_payment_intent(mock_payment_data)
        
        assert result["success"] == True
        assert result["payment_intent_id"] == "pi_123456789"
        assert result["client_secret"] == "pi_123456789_secret_abc123"
        assert result["status"] == "succeeded"
        mock_create.assert_called_once_with(
            amount=mock_payment_data["amount"],
            currency=mock_payment_data["currency"],
            description=mock_payment_data["description"],
            metadata=mock_payment_data["metadata"]
        )

def test_create_payment_intent_card_declined(mock_payment_data):
    """Test payment intent creation with declined card"""
    with patch('stripe.PaymentIntent.create') as mock_create:
        mock_create.side_effect = CardError(
            message="Your card was declined",
            param="card",
            code="card_declined"
        )
        
        result = create_payment_intent(mock_payment_data)
        
        assert result["success"] == False
        assert result["error_type"] == "card_error"
        assert "declined" in result["error_message"].lower()

def test_create_payment_intent_insufficient_funds(mock_payment_data):
    """Test payment intent creation with insufficient funds"""
    with patch('stripe.PaymentIntent.create') as mock_create:
        mock_create.side_effect = CardError(
            message="Your card has insufficient funds",
            param="card",
            code="insufficient_funds"
        )
        
        result = create_payment_intent(mock_payment_data)
        
        assert result["success"] == False
        assert result["error_type"] == "card_error"
        assert "insufficient" in result["error_message"].lower()

def test_confirm_payment_intent_success():
    """Test successful payment intent confirmation"""
    payment_intent_id = "pi_123456789"
    payment_method = "pm_card_visa"
    
    with patch('stripe.PaymentIntent.confirm') as mock_confirm:
        mock_confirm.return_value = {
            "id": payment_intent_id,
            "status": "succeeded",
            "charges": {"data": [{"status": "succeeded"}]}
        }
        
        result = confirm_payment_intent(payment_intent_id, payment_method)
        
        assert result["success"] == True
        assert result["status"] == "succeeded"
        mock_confirm.assert_called_once_with(
            payment_intent_id,
            payment_method=payment_method
        )

def test_cancel_payment_intent():
    """Test cancelling a payment intent"""
    payment_intent_id = "pi_123456789"
    
    with patch('stripe.PaymentIntent.cancel') as mock_cancel:
        mock_cancel.return_value = {
            "id": payment_intent_id,
            "status": "canceled"
        }
        
        result = cancel_payment_intent(payment_intent_id)
        
        assert result["success"] == True
        assert result["status"] == "canceled"
        mock_cancel.assert_called_once_with(payment_intent_id)

def test_refund_payment():
    """Test refunding a payment"""
    charge_id = "ch_123456789"
    refund_amount = 1500  # $15.00
    
    with patch('stripe.Refund.create') as mock_refund:
        mock_refund.return_value = {
            "id": "re_123456789",
            "amount": refund_amount,
            "charge": charge_id,
            "status": "succeeded"
        }
        
        result = create_refund(charge_id, refund_amount)
        
        assert result["success"] == True
        assert result["refund_id"] == "re_123456789"
        assert result["amount"] == refund_amount
        mock_refund.assert_called_once_with(
            charge=charge_id,
            amount=refund_amount
        )

def test_full_refund():
    """Test full refund (no amount specified)"""
    charge_id = "ch_123456789"
    
    with patch('stripe.Refund.create') as mock_refund:
        mock_refund.return_value = {
            "id": "re_123456789",
            "amount": 2999,
            "charge": charge_id,
            "status": "succeeded"
        }
        
        result = create_refund(charge_id)
        
        assert result["success"] == True
        assert result["refund_id"] == "re_123456789"

def test_create_customer_success():
    """Test creating a Stripe customer"""
    customer_data = {
        "email": "customer@example.com",
        "name": "John Doe",
        "metadata": {"user_id": "123"}
    }
    
    with patch('stripe.Customer.create') as mock_create:
        mock_create.return_value = {
            "id": "cus_123456789",
            "email": customer_data["email"],
            "name": customer_data["name"]
        }
        
        result = create_customer(customer_data)
        
        assert result["success"] == True
        assert result["customer_id"] == "cus_123456789"
        mock_create.assert_called_once_with(
            email=customer_data["email"],
            name=customer_data["name"],
            metadata=customer_data["metadata"]
        )

def test_create_subscription():
    """Test creating a subscription"""
    customer_id = "cus_123456789"
    price_id = "price_premium_monthly"
    
    with patch('stripe.Subscription.create') as mock_create:
        mock_create.return_value = {
            "id": "sub_123456789",
            "status": "active",
            "current_period_end": 1234567890,
            "customer": customer_id
        }
        
        result = create_subscription(customer_id, price_id)
        
        assert result["success"] == True
        assert result["subscription_id"] == "sub_123456789"
        assert result["status"] == "active"
        mock_create.assert_called_once_with(
            customer=customer_id,
            items=[{"price": price_id}]
        )

def test_cancel_subscription():
    """Test cancelling a subscription"""
    subscription_id = "sub_123456789"
    
    with patch('stripe.Subscription.delete') as mock_delete:
        mock_delete.return_value = {
            "id": subscription_id,
            "status": "canceled"
        }
        
        result = cancel_subscription(subscription_id)
        
        assert result["success"] == True
        assert result["status"] == "canceled"
        mock_delete.assert_called_once_with(subscription_id)

def test_webhook_event_processing():
    """Test processing Stripe webhook events"""
    webhook_payload = {
        "id": "evt_123456789",
        "type": "payment_intent.succeeded",
        "data": {
            "object": {
                "id": "pi_123456789",
                "amount": 2999,
                "customer": "cus_123456789"
            }
        }
    }
    
    with patch('handlers.payment_handlers.handle_successful_payment') as mock_handler:
        mock_handler.return_value = True
        
        result = process_webhook_event(webhook_payload)
        
        assert result["success"] == True
        assert result["event_type"] == "payment_intent.succeeded"
        mock_handler.assert_called_once_with(webhook_payload["data"]["object"])

def test_retrieve_payment_intent():
    """Test retrieving a payment intent"""
    payment_intent_id = "pi_123456789"
    
    with patch('stripe.PaymentIntent.retrieve') as mock_retrieve:
        mock_retrieve.return_value = {
            "id": payment_intent_id,
            "amount": 2999,
            "status": "succeeded"
        }
        
        result = retrieve_payment_intent(payment_intent_id)
        
        assert result["success"] == True
        assert result["payment_intent"]["id"] == payment_intent_id
        mock_retrieve.assert_called_once_with(payment_intent_id)

def test_list_payments_with_pagination():
    """Test listing payments with pagination"""
    limit = 10
    starting_after = "pi_123456789"
    
    with patch('stripe.PaymentIntent.list') as mock_list:
        mock_list.return_value = {
            "data": [
                {"id": "pi_111", "amount": 1000},
                {"id": "pi_222", "amount": 2000}
            ],
            "has_more": True
        }
        
        result = list_payments(limit=limit, starting_after=starting_after)
        
        assert result["success"] == True
        assert len(result["payments"]) == 2
        assert result["has_more"] == True
        mock_list.assert_called_once_with(
            limit=limit,
            starting_after=starting_after
        )

# Mock functions for payment operations
def create_payment_intent(payment_data):
    try:
        return {
            "success": True,
            "payment_intent_id": "pi_mock_123",
            "client_secret": "pi_mock_123_secret",
            "status": "requires_payment_method",
            "amount": payment_data.get("amount", 0),
            "currency": payment_data.get("currency", "usd")
        }
    except CardError as e:
        return {
            "success": False,
            "error_type": "card_error",
            "error_message": str(e)
        }

def confirm_payment_intent(payment_intent_id, payment_method):
    return {
        "success": True,
        "status": "succeeded",
        "payment_intent_id": payment_intent_id
    }

def cancel_payment_intent(payment_intent_id):
    return {
        "success": True,
        "status": "canceled",
        "payment_intent_id": payment_intent_id
    }

def create_refund(charge_id, amount=None):
    return {
        "success": True,
        "refund_id": "re_mock_123",
        "amount": amount or 2999,
        "charge_id": charge_id,
        "status": "succeeded"
    }

def create_customer(customer_data):
    return {
        "success": True,
        "customer_id": "cus_mock_123",
        "email": customer_data.get("email"),
        "name": customer_data.get("name")
    }

def create_subscription(customer_id, price_id):
    return {
        "success": True,
        "subscription_id": "sub_mock_123",
        "status": "active",
        "customer_id": customer_id,
        "price_id": price_id
    }

def cancel_subscription(subscription_id):
    return {
        "success": True,
        "subscription_id": subscription_id,
        "status": "canceled"
    }

def process_webhook_event(event_data):
    return {
        "success": True,
        "event_type": event_data.get("type", "unknown"),
        "processed": True
    }

def retrieve_payment_intent(payment_intent_id):
    return {
        "success": True,
        "payment_intent": {
            "id": payment_intent_id,
            "amount": 2999,
            "status": "succeeded"
        }
    }

def list_payments(limit=10, starting_after=None):
    return {
        "success": True,
        "payments": [
            {"id": "pi_1", "amount": 1000},
            {"id": "pi_2", "amount": 2000}
        ],
        "has_more": False
    }