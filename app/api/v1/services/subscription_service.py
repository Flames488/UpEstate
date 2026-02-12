from app.models.user import User
from app.models.subscription import Subscription
from app.extensions import db
from datetime import datetime, timedelta

class SubscriptionService:
    """Service for handling subscription business logic"""
    
    @staticmethod
    def ensure_active_subscription(user_id=None, tenant_id=None):
        """Ensure user has an active subscription"""
        if user_id:
            user = User.query.get(user_id)
            if not user:
                raise PermissionError("User not found")
            
            # Check if user has active subscription
            if not user.has_active_subscription():
                raise PermissionError("Active subscription required")
            
            # Also check for subscription record if exists
            if user.subscription_id:
                subscription = Subscription.query.filter_by(
                    stripe_subscription_id=user.subscription_id,
                    status="active"
                ).first()
                
                if not subscription:
                    raise PermissionError("Active subscription required")
            
            return True
            
        elif tenant_id:
            # For tenant-based subscriptions (multi-tenant support)
            subscription = Subscription.query.filter_by(
                tenant_id=tenant_id,
                status="active"
            ).first()
            
            if not subscription:
                raise PermissionError("Active subscription required")
            
            return True
        
        else:
            raise ValueError("Either user_id or tenant_id must be provided")
    
    @staticmethod
    def get_user_plan_limits(user_id):
        """Get plan limits for a user"""
        user = User.query.get(user_id)
        if not user:
            return None
        
        plan_limits = {
            'free': {
                'max_leads': 10,
                'max_properties': 5,
                'can_export': False,
                'api_access': False,
                'support_level': 'community'
            },
            'basic': {
                'max_leads': 100,
                'max_properties': 50,
                'can_export': True,
                'api_access': False,
                'support_level': 'email'
            },
            'pro': {
                'max_leads': 500,
                'max_properties': 200,
                'can_export': True,
                'api_access': True,
                'support_level': 'priority'
            },
            'enterprise': {
                'max_leads': -1,  # Unlimited
                'max_properties': -1,
                'can_export': True,
                'api_access': True,
                'support_level': 'dedicated'
            }
        }
        
        plan = user.subscription_plan or 'free'
        return plan_limits.get(plan, plan_limits['free'])
    
    @staticmethod
    def can_user_perform_action(user_id, action_type, current_count=0):
        """Check if user can perform an action based on plan limits"""
        user = User.query.get(user_id)
        if not user:
            return False
        
        # First check if user has active subscription
        try:
            SubscriptionService.ensure_active_subscription(user_id=user_id)
        except PermissionError:
            # For free plan users, we still allow some actions
            if user.subscription_plan != 'free':
                return False
        
        limits = SubscriptionService.get_user_plan_limits(user_id)
        
        if action_type == 'create_lead':
            max_leads = limits.get('max_leads', 0)
            return max_leads == -1 or current_count < max_leads
        
        elif action_type == 'create_property':
            max_properties = limits.get('max_properties', 0)
            return max_properties == -1 or current_count < max_properties
        
        elif action_type == 'export_data':
            return limits.get('can_export', False)
        
        elif action_type == 'use_api':
            return limits.get('api_access', False)
        
        return False
    
    @staticmethod
    def update_user_plan(user_id, plan_name, status='active'):
        """Update user's plan and corresponding limits"""
        user = User.query.get(user_id)
        if not user:
            return False
        
        user.subscription_plan = plan_name
        user.subscription_status = status
        
        # Update plan-specific limits
        limits = SubscriptionService.get_user_plan_limits(user_id)
        
        user.max_leads = limits.get('max_leads', 10)
        user.max_properties = limits.get('max_properties', 5)
        user.can_export_data = limits.get('can_export', False)
        user.has_api_access = limits.get('api_access', False)
        
        # If starting a trial, set trial end date
        if status == 'trialing' and not user.trial_ends_at:
            user.trial_ends_at = datetime.utcnow() + timedelta(days=14)
        
        db.session.commit()
        return True
    
    @staticmethod
    def get_subscription_summary(user_id):
        """Get comprehensive subscription summary for user"""
        user = User.query.get(user_id)
        if not user:
            return None
        
        limits = SubscriptionService.get_user_plan_limits(user_id)
        
        summary = {
            'user': user.to_dict(),
            'plan': user.subscription_plan,
            'status': user.subscription_status,
            'limits': limits,
            'has_active_subscription': user.has_active_subscription(),
            'trial_info': None
        }
        
        # Add trial info if applicable
        if user.trial_ends_at:
            now = datetime.utcnow()
            if user.trial_ends_at > now:
                days_left = (user.trial_ends_at - now).days
                summary['trial_info'] = {
                    'ends_at': user.trial_ends_at.isoformat(),
                    'days_left': days_left
                }
        
        # Add subscription details if exists
        if user.subscription_id:
            subscription = Subscription.query.filter_by(
                stripe_subscription_id=user.subscription_id
            ).first()
            
            if subscription:
                summary['subscription_details'] = subscription.to_dict()
                summary['days_until_renewal'] = subscription.days_until_renewal()
        
        return summary
    
    @staticmethod
    def check_usage_and_limits(user_id):
        """Check user's current usage against plan limits"""
        from app.models.lead import Lead
        from app.models.property import Property
        
        user = User.query.get(user_id)
        if not user:
            return None
        
        # Get counts
        lead_count = Lead.query.filter_by(agent_id=user_id).count()
        property_count = Property.query.filter_by(agent_id=user_id).count()
        
        limits = SubscriptionService.get_user_plan_limits(user_id)
        
        return {
            'leads': {
                'current': lead_count,
                'max': limits['max_leads'],
                'remaining': None if limits['max_leads'] == -1 else max(0, limits['max_leads'] - lead_count),
                'exceeded': limits['max_leads'] != -1 and lead_count >= limits['max_leads']
            },
            'properties': {
                'current': property_count,
                'max': limits['max_properties'],
                'remaining': None if limits['max_properties'] == -1 else max(0, limits['max_properties'] - property_count),
                'exceeded': limits['max_properties'] != -1 and property_count >= limits['max_properties']
            },
            'features': {
                'export': limits['can_export'],
                'api': limits['api_access']
            }
        }