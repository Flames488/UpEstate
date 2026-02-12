# app/notifications/notification_service.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import current_app
import threading
from app.notifications.email_templates import EmailTemplates
from app.models import AdminAlert, User
from app.extensions import db

class NotificationService:
    """Handle all notification logic"""
    
    @staticmethod
    def send_email(to_email, subject, html_content, from_email=None):
        """Send email asynchronously"""
        def send_async():
            try:
                if not from_email:
                    from_email = current_app.config.get('MAIL_DEFAULT_SENDER', 'noreply@yourapp.com')
                
                msg = MIMEMultipart('alternative')
                msg['Subject'] = subject
                msg['From'] = from_email
                msg['To'] = to_email
                
                # Attach HTML
                html_part = MIMEText(html_content, 'html')
                msg.attach(html_part)
                
                # Send via SMTP
                with smtplib.SMTP(
                    current_app.config.get('SMTP_HOST', 'localhost'),
                    current_app.config.get('SMTP_PORT', 587)
                ) as server:
                    if current_app.config.get('SMTP_USE_TLS', True):
                        server.starttls()
                    
                    if current_app.config.get('SMTP_USERNAME'):
                        server.login(
                            current_app.config.get('SMTP_USERNAME'),
                            current_app.config.get('SMTP_PASSWORD')
                        )
                    
                    server.send_message(msg)
                
                current_app.logger.info(f"Email sent to {to_email}: {subject}")
                
            except Exception as e:
                current_app.logger.error(f"Failed to send email to {to_email}: {str(e)}")
        
        # Start async thread
        thread = threading.Thread(target=send_async)
        thread.daemon = True
        thread.start()
    
    @classmethod
    def notify_payment_failed(cls, user, invoice_data, subscription=None):
        """Notify user and admins about payment failure"""
        
        # 1. Send email to user
        subject, html = EmailTemplates.payment_failed(user, invoice_data)
        cls.send_email(user.email, subject, html)
        
        # 2. Create admin alert
        alert = AdminAlert.create_payment_failed_alert(user, invoice_data, subscription)
        db.session.add(alert)
        
        # 3. Send email to admin team (for critical alerts)
        if current_app.config.get('ADMIN_ALERT_EMAILS'):
            admin_data = {
                'alert_type': 'payment_failed',
                'invoice_id': invoice_data.get('id'),
                'amount_due': invoice_data.get('amount_due'),
                'user_id': user.id,
                'user_email': user.email,
                'plan_name': subscription.plan_name if subscription else 'N/A',
                'alert_id': alert.id,
                'next_payment_attempt': invoice_data.get('next_payment_attempt')
            }
            
            admin_subject, admin_html = EmailTemplates.admin_payment_failed_alert(admin_data)
            
            for admin_email in current_app.config['ADMIN_ALERT_EMAILS']:
                cls.send_email(admin_email, admin_subject, admin_html)
        
        db.session.commit()
        
        current_app.logger.info(f"Payment failure notifications sent for user {user.id}")
    
    @classmethod
    def notify_plan_change(cls, user, old_plan, new_plan, effective_date=None):
        """Notify user about plan change"""
        
        # Send email to user
        subject, html = EmailTemplates.plan_change_confirmation(user, old_plan, new_plan, effective_date)
        cls.send_email(user.email, subject, html)
        
        # Create admin alert (info level)
        alert = AdminAlert.create_plan_change_alert(user, old_plan, new_plan)
        db.session.add(alert)
        db.session.commit()
        
        current_app.logger.info(f"Plan change notification sent for user {user.id} ({old_plan} → {new_plan})")
    
    @classmethod
    def notify_subscription_canceled(cls, user, plan_name, end_date=None):
        """Notify user about subscription cancellation"""
        
        # Send email to user
        subject, html = EmailTemplates.subscription_canceled(user, plan_name, end_date)
        cls.send_email(user.email, subject, html)
        
        # Create admin alert
        alert = AdminAlert.create_subscription_canceled_alert(user, {'plan_name': plan_name})
        db.session.add(alert)
        db.session.commit()
        
        current_app.logger.info(f"Subscription canceled notification sent for user {user.id}")
    
    @classmethod
    def notify_trial_ending(cls, user, days_left, end_date):
        """Notify user about trial ending"""
        # Similar implementation...
        pass