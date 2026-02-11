import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

# Advanced subscription plan fixtures
@pytest.fixture
def subscription_plans():
    """Fixture for subscription plans with features"""
    return {
        "free": {
            "price_id": None,
            "monthly_price": 0,
            "annual_price": 0,
            "features": {
                "max_users": 1,
                "storage_gb": 1,
                "api_calls_per_day": 1000,
                "support_level": "community",
                "custom_domain": False,
                "advanced_analytics": False,
                "webhooks": False,
                "sso": False
            },
            "limits": {
                "projects": 1,
                "team_members": 1,
                "exports_per_month": 10
            }
        },
        "pro": {
            "price_id": "price_pro_monthly",
            "monthly_price": 2999,
            "annual_price": 29999,
            "features": {
                "max_users": 10,
                "storage_gb": 100,
                "api_calls_per_day": 10000,
                "support_level": "priority",
                "custom_domain": True,
                "advanced_analytics": True,
                "webhooks": True,
                "sso": False
            },
            "limits": {
                "projects": 10,
                "team_members": 10,
                "exports_per_month": 1000
            }
        },
        "enterprise": {
            "price_id": "price_enterprise_monthly",
            "monthly_price": 9999,
            "annual_price": 99999,
            "features": {
                "max_users": 1000,
                "storage_gb": 1000,
                "api_calls_per_day": 100000,
                "support_level": "dedicated",
                "custom_domain": True,
                "advanced_analytics": True,
                "webhooks": True,
                "sso": True
            },
            "limits": {
                "projects": 100,
                "team_members": 100,
                "exports_per_month": 10000
            }
        }
    }

@pytest.fixture
def user_subscription():
    """Fixture for user subscription"""
    return {
        "id": "sub_test_123",
        "user_id": "user_test_123",
        "plan": "pro",
        "status": "active",
        "current_period_start": datetime.now().isoformat(),
        "current_period_end": (datetime.now() + timedelta(days=30)).isoformat(),
        "cancel_at_period_end": False,
        "price_id": "price_pro_monthly",
        "features": {
            "max_users": 10,
            "storage_gb": 100,
            "api_calls_per_day": 10000
        }
    }

# Advanced subscription plan tests
def test_subscription_downgrade_with_data_retention(user_subscription):
    """Test subscription downgrade with data retention"""
    new_plan = "free"
    
    with patch('services.storage.check_user_usage') as mock_usage:
        with patch('services.data_retention.archive_excess_data') as mock_archive:
            with patch('services.notification.send_downgrade_warning') as mock_notify:
                mock_usage.return_value = {
                    "storage_used_gb": 50,
                    "storage_limit_gb": 1,
                    "exceeds_limits": True
                }
                mock_archive.return_value = True
                mock_notify.return_value = True
                
                result = downgrade_subscription_with_checks(
                    user_subscription["user_id"],
                    user_subscription["id"],
                    new_plan
                )
                
                assert result["success"] == True
                assert result["requires_cleanup"] == True
                assert mock_archive.call_count >= 1

def test_subscription_downgrade_within_limits(user_subscription):
    """Test subscription downgrade when within new plan limits"""
    new_plan = "free"
    
    with patch('services.storage.check_user_usage') as mock_usage:
        with patch('services.subscription.downgrade_plan') as mock_downgrade:
            mock_usage.return_value = {
                "storage_used_gb": 0.5,
                "storage_limit_gb": 1,
                "exceeds_limits": False
            }
            mock_downgrade.return_value = True
            
            result = downgrade_subscription_with_checks(
                user_subscription["user_id"],
                user_subscription["id"],
                new_plan
            )
            
            assert result["success"] == True
            assert result["requires_cleanup"] == False

def test_subscription_downgrade_grace_period():
    """Test subscription downgrade with grace period"""
    user_id = "user_test_123"
    new_plan = "free"
    
    with patch('services.subscription.schedule_downgrade') as mock_schedule:
        with patch('services.email.send_downgrade_scheduled') as mock_email:
            mock_schedule.return_value = "scheduled_downgrade_123"
            mock_email.return_value = True
            
            result = schedule_downgrade_with_grace_period(
                user_id=user_id,
                new_plan=new_plan,
                grace_period_days=14
            )
            
            assert result["success"] == True
            assert result["scheduled"] == True
            assert result["effective_date"] is not None
            assert result["grace_period_days"] == 14

def test_subscription_upgrade_with_proration():
    """Test subscription upgrade with proration"""
    user_id = "user_test_123"
    current_subscription_id = "sub_current_123"
    new_price_id = "price_enterprise_monthly"
    
    with patch('stripe.Subscription.retrieve') as mock_retrieve:
        with patch('stripe.Subscription.modify') as mock_modify:
            mock_retrieve.return_value = {
                "id": current_subscription_id,
                "items": {"data": [{"id": "si_current"}]},
                "current_period_end": 1234567890
            }
            mock_modify.return_value = {
                "id": current_subscription_id,
                "status": "active",
                "plan_change": "prorated",
                "proration_date": 1234567890
            }
            
            result = upgrade_subscription_with_proration(
                user_id=user_id,
                subscription_id=current_subscription_id,
                new_price_id=new_price_id,
                prorate=True
            )
            
            assert result["success"] == True
            assert result["prorated"] == True
            mock_modify.assert_called_once()

def test_plan_enforcement_api_rate_limiting():
    """Test API rate limiting based on subscription plan"""
    user_id = "user_free_123"
    api_endpoint = "/api/v1/data/export"
    
    with patch('database.subscriptions.get_user_plan') as mock_get_plan:
        with patch('services.rate_limiter.check_api_limit') as mock_limiter:
            mock_get_plan.return_value = "free"
            mock_limiter.return_value = {
                "allowed": False,
                "limit": 100,
                "used": 100,
                "reset_in": 3600
            }
            
            result = check_api_access_by_plan(user_id, api_endpoint)
            
            assert result["allowed"] == False
            assert "limit" in result["message"]

def test_plan_enforcement_feature_access():
    """Test feature access based on subscription plan"""
    user_id = "user_free_123"
    feature = "advanced_analytics"
    
    with patch('database.subscriptions.get_user_plan') as mock_get_plan:
        with patch('database.features.is_feature_enabled') as mock_feature:
            mock_get_plan.return_value = "free"
            mock_feature.return_value = False
            
            result = check_feature_access(user_id, feature)
            
            assert result["allowed"] == False
            assert "upgrade" in result["message"].lower()

def test_subscription_trial_expiration():
    """Test trial expiration handling"""
    trial_user_id = "user_trial_123"
    
    with patch('database.subscriptions.get_trial_status') as mock_trial:
        with patch('services.email.send_trial_expiration_warning') as mock_email:
        with patch('services.billing.create_trial_conversion_offer') as mock_offer:
            mock_trial.return_value = {
                "expires_in_days": 1,
                "converted": False
            }
            mock_email.return_value = True
            mock_offer.return_value = {"offer_id": "offer_123"}
            
            result = handle_trial_expiration(trial_user_id)
            
            assert result["success"] == True
            assert result["action_required"] == True
            assert mock_email.call_count >= 1

def test_subscription_payment_method_required():
    """Test payment method requirement for paid plans"""
    user_id = "user_upgrading_123"
    new_plan = "pro"
    
    with patch('database.billing.get_payment_methods') as mock_payment_methods:
        with patch('services.email.send_payment_method_required') as mock_email:
            mock_payment_methods.return_value = []
            
            result = check_payment_method_requirement(user_id, new_plan)
            
            assert result["success"] == False
            assert result["requires_payment_method"] == True
            assert mock_email.call_count == 1

def test_subscription_annual_discount():
    """Test annual subscription discount calculation"""
    monthly_price = 2999
    annual_price = 29999
    
    discount = calculate_annual_discount(monthly_price, annual_price)
    
    assert discount["monthly_equivalent"] == annual_price / 12
    assert discount["annual_savings"] == (monthly_price * 12) - annual_price
    assert discount["discount_percentage"] == pytest.approx(
        ((monthly_price * 12 - annual_price) / (monthly_price * 12)) * 100,
        0.1
    )

def test_subscription_plan_comparison():
    """Test subscription plan comparison"""
    plans = ["free", "pro", "enterprise"]
    
    with patch('services.plans.get_plan_details') as mock_details:
        mock_details.side_effect = lambda p: {
            "free": {"features": {"storage_gb": 1}},
            "pro": {"features": {"storage_gb": 100}},
            "enterprise": {"features": {"storage_gb": 1000}}
        }[p]
        
        comparison = compare_subscription_plans(plans)
        
        assert len(comparison) == 3
        assert comparison["free"]["features"]["storage_gb"] == 1
        assert comparison["enterprise"]["features"]["storage_gb"] == 1000

def test_subscription_usage_tracking():
    """Test subscription usage tracking"""
    user_id = "user_pro_123"
    
    with patch('services.usage.track_api_call') as mock_track:
        with patch('services.usage.get_current_usage') as mock_usage:
            mock_track.return_value = True
            mock_usage.return_value = {
                "api_calls_today": 9500,
                "api_calls_limit": 10000,
                "percentage_used": 95
            }
            
            result = track_and_check_usage(user_id, "api_call")
            
            assert result["success"] == True
            assert result["remaining_calls"] == 500
            assert result["percentage_used"] == 95

def test_subscription_overage_charges():
    """Test subscription overage charges"""
    user_id = "user_pro_123"
    overage_data = {
        "extra_api_calls": 1000,
        "extra_storage_gb": 5,
        "extra_users": 2
    }
    
    with patch('services.billing.calculate_overage') as mock_calc:
        with patch('stripe.InvoiceItem.create') as mock_invoice:
            mock_calc.return_value = {
                "total": 4500,  # $45.00
                "breakdown": {
                    "api_calls": 1000,
                    "storage": 2500,
                    "users": 1000
                }
            }
            mock_invoice.return_value = {"id": "ii_overage_123"}
            
            result = apply_overage_charges(user_id, overage_data)
            
            assert result["success"] == True
            assert result["overage_amount"] == 4500
            assert mock_invoice.call_count >= 1

def test_subscription_plan_migration():
    """Test migrating users between subscription plans"""
    migration_spec = {
        "from_plan": "legacy_plan",
        "to_plan": "pro",
        "users": ["user_1", "user_2", "user_3"],
        "effective_date": datetime.now().isoformat(),
        "prorate": True
    }
    
    with patch('services.migration.migrate_user_plan') as mock_migrate:
        with patch('services.email.send_migration_notice') as mock_email:
            mock_migrate.return_value = True
            mock_email.return_value = True
            
            results = migrate_users_between_plans(migration_spec)
            
            assert results["success"] == True
            assert results["migrated"] == len(migration_spec["users"])
            assert mock_migrate.call_count == len(migration_spec["users"])

# Mock functions for subscription tests
def downgrade_subscription_with_checks(user_id, subscription_id, new_plan):
    # Check if user exceeds new plan limits
    usage = check_user_usage(user_id)
    new_plan_limits = get_plan_limits(new_plan)
    
    requires_cleanup = False
    if usage_exceeds_limits(usage, new_plan_limits):
        requires_cleanup = True
        # Archive excess data
        archive_excess_data(user_id, new_plan_limits)
        # Send notification
        send_downgrade_warning(user_id, new_plan, usage)
    
    # Proceed with downgrade
    result = downgrade_plan(user_id, subscription_id, new_plan)
    
    return {
        "success": result,
        "requires_cleanup": requires_cleanup,
        "downgraded_to": new_plan
    }

def schedule_downgrade_with_grace_period(user_id, new_plan, grace_period_days):
    effective_date = datetime.now() + timedelta(days=grace_period_days)
    
    job_id = schedule_downgrade(
        user_id=user_id,
        new_plan=new_plan,
        effective_date=effective_date.isoformat()
    )
    
    send_downgrade_scheduled(
        user_id=user_id,
        new_plan=new_plan,
        effective_date=effective_date.isoformat(),
        grace_period_days=grace_period_days
    )
    
    return {
        "success": True,
        "scheduled": True,
        "job_id": job_id,
        "effective_date": effective_date.isoformat(),
        "grace_period_days": grace_period_days
    }

def check_api_access_by_plan(user_id, endpoint):
    plan = get_user_plan(user_id)
    plan_limits = get_api_limits(plan)
    
    # Check rate limiting
    rate_limit = check_api_rate_limit(user_id, endpoint)
    if not rate_limit["allowed"]:
        return {
            "allowed": False,
            "message": f"API rate limit exceeded. Limit: {rate_limit['limit']}, Used: {rate_limit['used']}",
            "reset_in": rate_limit["reset_in"]
        }
    
    # Check endpoint access based on plan
    if not is_endpoint_allowed_for_plan(endpoint, plan):
        return {
            "allowed": False,
            "message": f"Endpoint not available for {plan} plan. Please upgrade.",
            "required_plan": get_required_plan_for_endpoint(endpoint)
        }
    
    return {"allowed": True, "message": "Access granted"}

def calculate_annual_discount(monthly_price, annual_price):
    monthly_equivalent = annual_price / 12
    annual_savings = (monthly_price * 12) - annual_price
    discount_percentage = (annual_savings / (monthly_price * 12)) * 100 if monthly_price > 0 else 0
    
    return {
        "monthly_equivalent": monthly_equivalent,
        "annual_savings": annual_savings,
        "discount_percentage": discount_percentage,
        "monthly_price": monthly_price,
        "annual_price": annual_price
    }

def track_and_check_usage(user_id, action):
    # Track the usage
    track_usage(user_id, action)
    
    # Get current usage
    usage = get_current_usage(user_id)
    limits = get_user_limits(user_id)
    
    remaining = limits.get("api_calls_limit", 0) - usage.get("api_calls_today", 0)
    percentage_used = (usage.get("api_calls_today", 0) / limits.get("api_calls_limit", 1)) * 100
    
    return {
        "success": True,
        "remaining_calls": max(remaining, 0),
        "percentage_used": percentage_used,
        "limits": limits,
        "usage": usage
    }