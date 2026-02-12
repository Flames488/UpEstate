import json
from flask import request, current_app
from .stripe_service import stripe_service


class StripeWebhookHandler:
    """Handler for Stripe webhook events with proper isolation"""
    
    @staticmethod
    def handle_webhook():
        """
        Main entry point for Stripe webhooks
        Should be called from your Flask route
        """
        payload = request.get_data()
        sig_header = request.headers.get('Stripe-Signature')
        webhook_secret = current_app.config.get('STRIPE_WEBHOOK_SECRET')
        
        try:
            # Validate the webhook event
            event = stripe_service.handle_webhook_event(
                payload, sig_header, webhook_secret
            )
            
            # Route the event to appropriate handler
            event_type = event['type']
            
            if event_type == 'customer.subscription.created':
                return StripeWebhookHandler._handle_subscription_created(event)
            elif event_type == 'customer.subscription.updated':
                return StripeWebhookHandler._handle_subscription_updated(event)
            elif event_type == 'customer.subscription.deleted':
                return StripeWebhookHandler._handle_subscription_deleted(event)
            elif event_type == 'invoice.payment_succeeded':
                return StripeWebhookHandler._handle_payment_succeeded(event)
            elif event_type == 'invoice.payment_failed':
                return StripeWebhookHandler._handle_payment_failed(event)
            else:
                # Log unhandled event types
                print(f"Unhandled event type: {event_type}")
                return {'status': 'unhandled'}, 200
                
        except Exception as e:
            # Log error and return appropriate status
            print(f"Webhook error: {str(e)}")
            return {'error': str(e)}, 400
    
    @staticmethod
    def _handle_subscription_created(event):
        """Handle subscription.created event"""
        subscription = event['data']['object']
        # Your business logic here - call service layer, not Stripe directly
        return {'status': 'success'}, 200
    
    @staticmethod
    def _handle_subscription_updated(event):
        """Handle subscription.updated event"""
        subscription = event['data']['object']
        # Your business logic here
        return {'status': 'success'}, 200
    
    @staticmethod
    def _handle_subscription_deleted(event):
        """Handle subscription.deleted event"""
        subscription = event['data']['object']
        # Your business logic here
        return {'status': 'success'}, 200
    
    # Add other event handlers as needed