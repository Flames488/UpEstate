from datetime import datetime, timedelta
from typing import Optional, Tuple
from dataclasses import dataclass
from flask import Flask, jsonify, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import current_user, login_required

# Initialize SQLAlchemy
db = SQLAlchemy()

class AutomationRun(db.Model):
    """Represents an individual automation execution attempt."""
    
    __tablename__ = 'automation_runs'
    
    id = db.Column(db.Integer, primary_key=True, doc="Unique identifier for the run")
    user_id = db.Column(db.Integer, nullable=False, index=True, 
                       doc="ID of the user who initiated the run")
    automation_id = db.Column(db.Integer, nullable=False, index=True,
                            doc="ID of the automation template being executed")
    status = db.Column(db.String(20), default="PENDING", nullable=False,
                      doc="Execution status: PENDING, RUNNING, COMPLETED, FAILED")
    started_at = db.Column(db.DateTime, default=db.func.now(), nullable=False,
                          doc="Timestamp when the execution was initiated")
    completed_at = db.Column(db.DateTime, nullable=True,
                           doc="Timestamp when the execution finished")
    
    # Add indexes for frequently queried columns
    __table_args__ = (
        db.Index('idx_user_started', 'user_id', 'started_at'),
    )
    
    def to_dict(self) -> dict:
        """Serialize the object to a dictionary."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'automation_id': self.automation_id,
            'status': self.status,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    max_runs_per_day: int = 100
    window_hours: int = 24


class AutomationRateLimiter:
    """Manages rate limiting for automation executions."""
    
    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
    
    def check_rate_limit(self, user_id: int) -> Tuple[bool, Optional[str]]:
        """
        Check if a user has exceeded their daily automation limit.
        
        Args:
            user_id: The ID of the user to check
            
        Returns:
            Tuple of (is_allowed, error_message)
        """
        try:
            run_count = self._get_daily_run_count(user_id)
            
            if run_count >= self.config.max_runs_per_day:
                error_msg = (
                    f"Daily automation limit of {self.config.max_runs_per_day} "
                    f"runs reached. Please try again tomorrow."
                )
                return False, error_msg
            
            return True, None
            
        except Exception as e:
            # Log the error but allow the request to proceed
            # This prevents rate limiting from becoming a single point of failure
            current_app.logger.error(f"Rate limit check failed: {str(e)}")
            return True, None
    
    def _get_daily_run_count(self, user_id: int) -> int:
        """Get the number of runs for a user within the rate limit window."""
        window_start = datetime.utcnow() - timedelta(hours=self.config.window_hours)
        
        count = AutomationRun.query.filter(
            AutomationRun.user_id == user_id,
            AutomationRun.started_at >= window_start
        ).count()
        
        return count


# Import the blueprint (assuming it exists in the billing module)
from app.billing.webhook import bp as paystack_webhook

def create_app():
    """Application factory function to create and configure the Flask app."""
    app = Flask(__name__)
    
    # Configure the app (you should add your config settings here)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'  # Example
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize extensions with the app
    db.init_app(app)
    
    # Register blueprints
    app.register_blueprint(paystack_webhook)
    
    # Register routes
    register_routes(app)
    
    return app


def register_routes(app):
    """Register all application routes."""
    
    @app.route('/api/automations/<int:automation_id>/run', methods=['POST'])
    @login_required
    def run_automation(automation_id: int):
        """
        Execute an automation with rate limiting.
        
        Returns:
            200: Automation started successfully
            429: Rate limit exceeded
            400: Invalid request
            500: Server error
        """
        # Initialize rate limiter (could be a singleton in production)
        rate_limiter = AutomationRateLimiter()
        
        # Check rate limit
        is_allowed, error_message = rate_limiter.check_rate_limit(current_user.id)
        
        if not is_allowed:
            return jsonify({
                'error': 'Rate limit exceeded',
                'message': error_message,
                'retry_after': '24 hours'
            }), 429
        
        # Create automation run record
        automation_run = AutomationRun(
            user_id=current_user.id,
            automation_id=automation_id,
            status='PENDING'
        )
        
        try:
            db.session.add(automation_run)
            db.session.commit()
            
            # Asynchronously execute the automation (using Celery, RQ, etc.)
            # celery.send_task('execute_automation', args=[automation_run.id])
            
            return jsonify({
                'message': 'Automation execution started',
                'run_id': automation_run.id,
                'status': automation_run.status
            }), 202  # 202 Accepted
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to start automation: {str(e)}")
            return jsonify({
                'error': 'Failed to start automation execution'
            }), 500


# Utility function for direct usage if needed
def can_user_run_automation(user_id: int, max_runs: int = 100) -> bool:
    """
    Convenience function to check if a user can run an automation.
    
    Args:
        user_id: The user's ID
        max_runs: Maximum allowed runs per day
        
    Returns:
        True if the user can run an automation, False otherwise
    """
    rate_limiter = AutomationRateLimiter(
        RateLimitConfig(max_runs_per_day=max_runs)
    )
    can_run, _ = rate_limiter.check_rate_limit(user_id)
    return can_run