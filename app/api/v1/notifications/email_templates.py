# app/notifications/email_templates.py
from flask import render_template_string
from datetime import datetime

class EmailTemplates:
    """Email template definitions"""
    
    @staticmethod
    def payment_failed(user, invoice_data):
        """Payment failed email template"""
        subject = f"Payment Failed - Action Required"
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #dc3545; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 30px; background: #f8f9fa; }}
                .button {{ display: inline-block; background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; }}
                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #6c757d; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Payment Failed</h1>
                </div>
                <div class="content">
                    <p>Hello {user.full_name},</p>
                    
                    <p>We were unable to process your recent payment for your subscription.</p>
                    
                    <div style="background: white; padding: 20px; border-radius: 4px; margin: 20px 0;">
                        <h3>Payment Details:</h3>
                        <p><strong>Invoice ID:</strong> {invoice_data.get('id', 'N/A')}</p>
                        <p><strong>Amount Due:</strong> ${invoice_data.get('amount_due', 0) / 100:.2f}</p>
                        <p><strong>Due Date:</strong> {datetime.fromtimestamp(invoice_data.get('created')).strftime('%B %d, %Y')}</p>
                    </div>
                    
                    <p>Your account access has been temporarily suspended until the payment is completed.</p>
                    
                    <p style="text-align: center; margin: 30px 0;">
                        <a href="{invoice_data.get('hosted_invoice_url', '#')}" class="button">
                            Update Payment Method
                        </a>
                    </p>
                    
                    <p>If you believe this is an error, or need assistance, please contact our support team immediately.</p>
                    
                    <p><strong>Need help?</strong><br>
                    Contact support: support@yourapp.com<br>
                    Call us: (555) 123-4567</p>
                </div>
                <div class="footer">
                    <p>© {datetime.now().year} Your App Name. All rights reserved.</p>
                    <p>This is an automated message, please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return subject, html
    
    @staticmethod
    def plan_change_confirmation(user, old_plan, new_plan, effective_date=None):
        """Plan change confirmation email"""
        subject = f"Your Subscription Plan Has Been Updated"
        
        if effective_date:
            effective_str = f"effective {effective_date.strftime('%B %d, %Y')}"
        else:
            effective_str = "effective immediately"
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #007bff; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 30px; background: #f8f9fa; }}
                .plan-box {{ background: white; padding: 20px; border-radius: 4px; margin: 20px 0; border-left: 4px solid #007bff; }}
                .features {{ margin: 20px 0; }}
                .feature-item {{ margin: 10px 0; }}
                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #6c757d; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Plan Updated Successfully</h1>
                </div>
                <div class="content">
                    <p>Hello {user.full_name},</p>
                    
                    <p>Your subscription plan has been updated {effective_str}.</p>
                    
                    <div class="plan-box">
                        <h3>Plan Change Summary:</h3>
                        <p><strong>Previous Plan:</strong> {old_plan.capitalize()}</p>
                        <p><strong>New Plan:</strong> {new_plan.capitalize()}</p>
                        <p><strong>Change Date:</strong> {datetime.utcnow().strftime('%B %d, %Y')}</p>
                    </div>
                    
                    <div class="features">
                        <h4>Your new plan includes:</h4>
                        {"<p>• Unlimited leads and properties</p>" if new_plan == 'enterprise' else f"<p>• Up to {500 if new_plan == 'pro' else 100 if new_plan == 'basic' else 10} leads</p>"}
                        {"<p>• Data export capabilities</p>" if new_plan in ['basic', 'pro', 'enterprise'] else ""}
                        {"<p>• API access</p>" if new_plan in ['pro', 'enterprise'] else ""}
                        {"<p>• Advanced analytics</p>" if new_plan in ['pro', 'enterprise'] else ""}
                    </div>
                    
                    <p>If you have any questions about your new plan features or billing, please don't hesitate to contact our support team.</p>
                    
                    <p><strong>Next Billing Date:</strong><br>
                    Your next invoice will be generated on your regular billing cycle.</p>
                    
                    <p><strong>Need help?</strong><br>
                    Contact support: support@yourapp.com<br>
                    Visit our help center: https://help.yourapp.com</p>
                </div>
                <div class="footer">
                    <p>© {datetime.now().year} Your App Name. All rights reserved.</p>
                    <p>This is an automated message, please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return subject, html
    
    @staticmethod
    def subscription_canceled(user, plan_name, end_date=None):
        """Subscription canceled email"""
        subject = f"We're Sorry to See You Go"
        
        if end_date:
            end_str = f"Your subscription will remain active until {end_date.strftime('%B %d, %Y')}."
        else:
            end_str = "Your subscription has been canceled immediately."
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #6c757d; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 30px; background: #f8f9fa; }}
                .cta-box {{ background: white; padding: 20px; border-radius: 4px; margin: 20px 0; text-align: center; border: 2px dashed #dee2e6; }}
                .button {{ display: inline-block; background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; }}
                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #6c757d; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Subscription Canceled</h1>
                </div>
                <div class="content">
                    <p>Hello {user.full_name},</p>
                    
                    <p>Your {plan_name.capitalize()} subscription has been canceled as requested.</p>
                    
                    <p>{end_str}</p>
                    
                    <p>After cancellation, your account will be downgraded to our Free plan, which includes:</p>
                    <ul>
                        <li>Up to 10 leads</li>
                        <li>Up to 5 properties</li>
                        <li>Basic features</li>
                    </ul>
                    
                    <div class="cta-box">
                        <h3>Changed Your Mind?</h3>
                        <p>You can reactivate your subscription at any time to regain access to all premium features.</p>
                        <p style="margin-top: 20px;">
                            <a href="https://app.yourapp.com/billing/restore" class="button">
                                Reactivate Subscription
                            </a>
                        </p>
                    </div>
                    
                    <p>We'd love to hear your feedback on how we can improve. Please take a moment to <a href="https://yourapp.com/feedback">share your thoughts</a>.</p>
                    
                    <p><strong>Account Data:</strong><br>
                    Your account data will be preserved for 30 days. After that period, it may be permanently deleted.</p>
                    
                    <p>Thank you for being a valued customer.</p>
                    
                    <p><strong>Need help?</strong><br>
                    Contact support: support@yourapp.com</p>
                </div>
                <div class="footer">
                    <p>© {datetime.now().year} Your App Name. All rights reserved.</p>
                    <p>This is an automated message, please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return subject, html
    
    @staticmethod
    def admin_payment_failed_alert(alert_data, user_count=1):
        """Admin alert email for payment failures"""
        subject = f"[ACTION REQUIRED] Payment Failed - {user_count} User(s) Affected"
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                .container {{ max-width: 800px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #dc3545; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 30px; background: #f8f9fa; }}
                .alert-box {{ background: white; padding: 20px; border-radius: 4px; margin: 20px 0; border-left: 4px solid #dc3545; }}
                .user-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                .user-table th, .user-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
                .user-table th {{ background-color: #f8f9fa; }}
                .button {{ display: inline-block; background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; }}
                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #6c757d; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>⚠️ Admin Alert: Payment Failure</h1>
                </div>
                <div class="content">
                    <p><strong>Attention Admin Team,</strong></p>
                    
                    <p>A payment failure has occurred requiring manual review.</p>
                    
                    <div class="alert-box">
                        <h3>Alert Details:</h3>
                        <p><strong>Alert Type:</strong> {alert_data.get('alert_type', 'payment_failed')}</p>
                        <p><strong>Severity:</strong> <span style="color: #dc3545;">CRITICAL</span></p>
                        <p><strong>Affected Users:</strong> {user_count} user(s)</p>
                        <p><strong>Invoice ID:</strong> {alert_data.get('invoice_id', 'N/A')}</p>
                        <p><strong>Amount Due:</strong> ${alert_data.get('amount_due', 0) / 100:.2f}</p>
                        <p><strong>Next Payment Attempt:</strong> {datetime.fromtimestamp(alert_data.get('next_payment_attempt')).strftime('%B %d, %Y %H:%M UTC') if alert_data.get('next_payment_attempt') else 'N/A'}</p>
                    </div>
                    
                    <p><strong>Action Required:</strong></p>
                    <ol>
                        <li>Review the failed payment in Stripe Dashboard</li>
                        <li>Check if user needs assistance updating payment method</li>
                        <li>Consider reaching out to user if multiple failures occur</li>
                        <li>Monitor for potential fraudulent activity</li>
                    </ol>
                    
                    <p style="text-align: center; margin: 30px 0;">
                        <a href="https://dashboard.stripe.com/payments" class="button" target="_blank">
                            View in Stripe Dashboard
                        </a>
                        <a href="https://admin.yourapp.com/alerts/{alert_data.get('alert_id')}" class="button" style="margin-left: 10px;">
                            View Alert Details
                        </a>
                    </p>
                    
                    <p><strong>User Information:</strong></p>
                    <table class="user-table">
                        <tr>
                            <th>User ID</th>
                            <th>Email</th>
                            <th>Plan</th>
                            <th>Amount Due</th>
                            <th>Action</th>
                        </tr>
                        <tr>
                            <td>{alert_data.get('user_id')}</td>
                            <td>{alert_data.get('user_email')}</td>
                            <td>{alert_data.get('plan_name', 'N/A')}</td>
                            <td>${alert_data.get('amount_due', 0) / 100:.2f}</td>
                            <td><a href="https://admin.yourapp.com/users/{alert_data.get('user_id')}">View User</a></td>
                        </tr>
                    </table>
                    
                    <p style="margin-top: 30px;">
                        <strong>Note:</strong> User access has been temporarily suspended. 
                        They will be automatically restored upon successful payment.
                    </p>
                </div>
                <div class="footer">
                    <p>© {datetime.now().year} Your App Name Admin System</p>
                    <p>This is an automated alert. Please review and take appropriate action.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return subject, html