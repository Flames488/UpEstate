from fastapi import APIRouter, Request, Depends, Header, HTTPException
from sqlalchemy.orm import Session
import json
from datetime import datetime, timedelta
import hashlib
from typing import Optional

from app.db.session import get_db
from app.config.settings import settings
from app.models.webhook_event import WebhookEvent  # You'll need to adapt your model
from app.models.user import User
from app.models.subscription import Subscription

router = APIRouter()

class WebhookSecurity:
    """Security utilities for webhook processing"""
    
    @staticmethod
    def verify_paystack_signature(payload: bytes, signature: str, timestamp: int, secret: str) -> bool:
        """Verify Paystack webhook signature"""
        try:
            # Import or implement Paystack signature verification
            # This is a placeholder - you need to implement actual Paystack verification
            import hashlib
            import hmac
            
            expected_signature = hmac.new(
                secret.encode(),
                f"{timestamp}.{payload.decode()}".encode(),
                hashlib.sha512
            ).hexdigest()
            
            if not hmac.compare_digest(expected_signature, signature):
                raise HTTPException(status_code=400, detail="Invalid signature")
            
            return True
            
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Signature verification failed: {str(e)}")
    
    @staticmethod
    def calculate_payload_hash(payload: bytes) -> str:
        """Calculate hash of payload for duplicate detection"""
        return hashlib.sha256(payload).hexdigest()
    
    @staticmethod
    def check_replay_attack(event_timestamp: int) -> bool:
        """Check if event is too old (replay attack)"""
        try:
            event_time = datetime.fromtimestamp(event_timestamp)
            time_diff = datetime.utcnow() - event_time
            
            # Reject events older than 5 minutes
            if time_diff > timedelta(minutes=5):
                return False
            return True
        except:
            return True  # Be lenient if timestamp parsing fails

class WebhookProcessor:
    """Process webhook events with idempotency and error handling"""
    
    @staticmethod
    def process_with_idempotency(
        db: Session,
        event_data: dict,
        handler_func,
        *handler_args
    ) -> tuple[bool, str, bool]:
        """
        Process event with idempotency protection
        Returns: (success, result, already_processed)
        """
        event_id = event_data.get("event")
        event_type = event_data.get("data", {}).get("status")
        event_timestamp = event_data.get("sent_at", datetime.utcnow().timestamp())
        
        # Check replay attack
        if not WebhookSecurity.check_replay_attack(event_timestamp):
            return False, "Event timestamp too old - possible replay attack", False
        
        # Calculate payload hash for duplicate detection
        payload_hash = WebhookSecurity.calculate_payload_hash(
            json.dumps(event_data).encode('utf-8')
        )
        
        # Check if event already processed
        webhook_event = db.query(WebhookEvent).filter_by(
            provider_event_id=event_id,
            provider="paystack"
        ).first()
        
        if webhook_event:
            # If event exists and is already completed
            if webhook_event.status == 'completed':
                return True, "Already processed", True
            
            # If event exists but failed and should retry
            if webhook_event.status == 'failed':
                return False, "Previously failed", False
            
            # Update existing event
            webhook_event.attempts += 1
            webhook_event.last_processed_at = datetime.utcnow()
        else:
            # Create new event
            webhook_event = WebhookEvent(
                provider_event_id=event_id,
                provider="paystack",
                event_type=event_type,
                payload=json.dumps(event_data),
                payload_hash=payload_hash,
                status='processing',
                attempts=1,
                metadata={
                    'event_timestamp': event_timestamp,
                    'received_at': datetime.utcnow().isoformat()
                }
            )
            db.add(webhook_event)
        
        try:
            db.commit()
        except:
            db.rollback()
            return False, "Database error", False
        
        try:
            # Process the event
            result = handler_func(event_data, *handler_args)
            
            # Mark as completed
            webhook_event.status = 'completed'
            webhook_event.processed_data = result
            webhook_event.completed_at = datetime.utcnow()
            db.commit()
            
            return True, result, False
            
        except Exception as e:
            db.rollback()
            
            # Mark as failed
            webhook_event.status = 'failed'
            webhook_event.error_message = str(e)
            webhook_event.last_error_at = datetime.utcnow()
            
            # Check if we should retry
            max_retries = 3  # Configure this as needed
            max_retries_exceeded = webhook_event.attempts >= max_retries
            
            if max_retries_exceeded:
                WebhookProcessor._send_to_dead_letter_queue(webhook_event, str(e))
            
            db.commit()
            
            return False, str(e), False
    
    @staticmethod
    def _send_to_dead_letter_queue(webhook_event: WebhookEvent, error_msg: str):
        """Send failed events to dead letter queue for manual review"""
        # Store in separate table or external service
        # For logging purposes
        dead_letter_event = {
            'webhook_event_id': webhook_event.id,
            'provider_event_id': webhook_event.provider_event_id,
            'event_type': webhook_event.event_type,
            'payload': webhook_event.payload,
            'error_message': error_msg,
            'attempts': webhook_event.attempts,
            'failed_at': datetime.utcnow().isoformat()
        }
        
        # Log to your preferred logging system
        print(f"DEAD LETTER QUEUE: {json.dumps(dead_letter_event)}")

def _route_paystack_event(event_data: dict, event_id: str, db: Session):
    """Route Paystack event to appropriate handler"""
    
    event_type = event_data.get("event")
    data_object = event_data.get("data", {})
    
    # Map Paystack event types to handler functions
    event_handlers = {
        "charge.success": handle_payment_success,
        "subscription.create": handle_subscription_created,
        "subscription.disable": handle_subscription_cancelled,
        "invoice.create": handle_invoice_created,
        "invoice.payment_failed": handle_payment_failed,
        "transfer.success": handle_transfer_success,
        # Add more Paystack event types as needed
    }
    
    handler = event_handlers.get(event_type)
    
    if not handler:
        return {"status": "unhandled", "event_type": event_type}
    
    # Add webhook event ID to metadata for tracking
    if isinstance(data_object, dict):
        data_object["_webhook_event_id"] = event_id
    
    # Call the handler
    return handler(data_object, event_id, db)

# Handler functions for Paystack
def handle_payment_success(data: dict, event_id: str, db: Session):
    """Handle successful payment"""
    customer_email = data.get("customer", {}).get("email")
    amount = data.get("amount")
    reference = data.get("reference")
    
    # Find user by email or reference
    user = db.query(User).filter_by(email=customer_email).first()
    
    if user:
        # Update user's subscription status
        user.subscription_status = "active"
        db.commit()
    
    return {
        "status": "success",
        "action": "payment_success",
        "reference": reference,
        "amount": amount
    }

def handle_subscription_created(data: dict, event_id: str, db: Session):
    """Handle new subscription creation"""
    subscription_id = data.get("id")
    customer_email = data.get("customer", {}).get("email")
    plan_code = data.get("plan", {}).get("plan_code")
    
    user = db.query(User).filter_by(email=customer_email).first()
    
    if user:
        # Create or update subscription record
        subscription = Subscription(
            user_id=user.id,
            provider_subscription_id=subscription_id,
            plan_code=plan_code,
            status="active",
            provider="paystack"
        )
        db.add(subscription)
        db.commit()
    
    return {
        "status": "success",
        "action": "subscription_created",
        "subscription_id": subscription_id
    }

def handle_subscription_cancelled(data: dict, event_id: str, db: Session):
    """Handle subscription cancellation"""
    subscription_id = data.get("id")
    
    # Update subscription status
    subscription = db.query(Subscription).filter_by(
        provider_subscription_id=subscription_id
    ).first()
    
    if subscription:
        subscription.status = "cancelled"
        subscription.cancelled_at = datetime.utcnow()
        db.commit()
    
    return {
        "status": "success",
        "action": "subscription_cancelled",
        "subscription_id": subscription_id
    }

def handle_invoice_created(data: dict, event_id: str, db: Session):
    """Handle invoice creation"""
    # Implement invoice handling logic
    return {"status": "success", "action": "invoice_created"}

def handle_payment_failed(data: dict, event_id: str, db: Session):
    """Handle failed payment"""
    # Implement payment failure logic
    return {"status": "success", "action": "payment_failed"}

def handle_transfer_success(data: dict, event_id: str, db: Session):
    """Handle successful transfer"""
    # Implement transfer success logic
    return {"status": "success", "action": "transfer_success"}

@router.post("/webhooks/paystack")
async def paystack_webhook(
    request: Request,
    x_paystack_signature: str = Header(...),
    x_paystack_timestamp: str = Header(...),
    db: Session = Depends(get_db),
):
    payload = await request.body()
    
    try:
        # Convert timestamp to int
        timestamp = int(x_paystack_timestamp)
        
        # 1️⃣ Verify signature + timestamp
        WebhookSecurity.verify_paystack_signature(
            payload=payload,
            signature=x_paystack_signature,
            timestamp=timestamp,
            secret=settings.PAYSTACK_WEBHOOK_SECRET,
        )
        
        # Parse the JSON data
        event_data = await request.json()
        event_id = event_data.get("event")
        event_type = event_data.get("data", {}).get("status")
        
        if not event_id:
            raise HTTPException(status_code=400, detail="No event ID in webhook")
        
        # 2️⃣ Process with idempotency protection
        success, result, already_processed = WebhookProcessor.process_with_idempotency(
            db=db,
            event_data=event_data,
            handler_func=_route_paystack_event,
            event_id,  # Additional arguments for handler
            db
        )
        
        if already_processed:
            return {
                "success": True,
                "message": "Event already processed",
                "event_id": event_id
            }
        
        if success:
            return {
                "success": True,
                "event_id": event_id,
                "result": result
            }
        else:
            # Return 202 Accepted for retryable errors
            raise HTTPException(
                status_code=202,
                detail={
                    "success": False,
                    "error": "Failed to process event",
                    "event_id": event_id,
                    "retryable": True
                }
            )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal server error",
                "message": str(e)
            }
        )

# Admin endpoints (consider adding authentication)
@router.post("/webhooks/retry/{event_id}")
async def retry_webhook(event_id: str, db: Session = Depends(get_db)):
    """Admin endpoint to retry failed webhook events"""
    webhook_event = db.query(WebhookEvent).filter_by(
        provider_event_id=event_id,
        provider="paystack"
    ).first()
    
    if not webhook_event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    if webhook_event.status != "failed":
        raise HTTPException(status_code=400, detail="Event is not in failed state")
    
    # Reset for retry
    webhook_event.status = "pending"
    webhook_event.error_message = None
    webhook_event.last_error_at = None
    db.commit()
    
    return {
        "success": True,
        "message": "Event marked for retry",
        "event_id": event_id
    }

@router.get("/webhooks/status/{event_id}")
async def get_webhook_status(event_id: str, db: Session = Depends(get_db)):
    """Check status of a webhook event"""
    webhook_event = db.query(WebhookEvent).filter_by(
        provider_event_id=event_id,
        provider="paystack"
    ).first()
    
    if not webhook_event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    return {
        "id": webhook_event.id,
        "provider_event_id": webhook_event.provider_event_id,
        "provider": webhook_event.provider,
        "event_type": webhook_event.event_type,
        "status": webhook_event.status,
        "attempts": webhook_event.attempts,
        "error_message": webhook_event.error_message,
        "created_at": webhook_event.created_at,
        "completed_at": webhook_event.completed_at,
        "last_error_at": webhook_event.last_error_at
    }