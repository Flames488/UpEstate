from datetime import datetime, timedelta
from typing import Dict, Optional
from models.user_flags import UserFlag
from extensions import db


class AbuseDetector:
    """Automated abuse detection and prevention system."""
    
    # Configuration
    MAX_ABUSE_SCORE = 10
    LOCK_DURATION_HOURS = 6
    SCORE_DECAY_HOURS = 24
    
    # Event point values
    POINTS = {
        'rate_limit': 3,
        'failed_automation': 1,
        'suspicious_pattern': 5,
        'resource_abuse': 2,
    }
    
    def __init__(self):
        self._plan_limits = {
            "free": 10,
            "pro": 100,
            "enterprise": 1000
        }
    
    def record_event(self, user_id: int, event_type: str, 
                    severity: str = 'medium') -> UserFlag:
        """
        Record an abuse-related event for a user.
        
        Args:
            user_id: The user ID
            event_type: Type of event (rate_limit, failed_automation, etc.)
            severity: Event severity (low, medium, high)
            
        Returns:
            Updated UserFlag object
        """
        flag = UserFlag.query.filter_by(user_id=user_id).first()
        if not flag:
            flag = UserFlag(user_id=user_id)
            db.session.add(flag)
        
        # Apply score decay before adding new points
        self._apply_score_decay(flag)
        
        # Calculate points based on event type and severity
        base_points = self.POINTS.get(event_type, 1)
        multiplier = {'low': 0.5, 'medium': 1, 'high': 2}.get(severity, 1)
        points = int(base_points * multiplier)
        
        flag.abuse_score += points
        
        # Auto-lock if threshold exceeded
        if flag.abuse_score >= self.MAX_ABUSE_SCORE and not flag.is_locked():
            flag.locked_until = datetime.utcnow() + timedelta(
                hours=self.LOCK_DURATION_HOURS
            )
        
        db.session.commit()
        return flag
    
    def check_user_access(self, user_id: int) -> bool:
        """
        Check if user is allowed to perform actions.
        
        Args:
            user_id: The user ID to check
            
        Returns:
            True if user can proceed, False if locked
        """
        flag = UserFlag.query.filter_by(user_id=user_id).first()
        
        if not flag:
            return True
        
        # Apply decay before checking
        self._apply_score_decay(flag)
        
        if flag.is_locked():
            return False
        
        db.session.commit()
        return True
    
    def enforce_access(self, user_id: int) -> None:
        """
        Enforce access control. Raises exception if user is locked.
        
        Args:
            user_id: The user ID to check
            
        Raises:
            AccountLockedError: If user is temporarily locked
        """
        if not self.check_user_access(user_id):
            flag = UserFlag.query.filter_by(user_id=user_id).first()
            remaining = flag.remaining_lock_time()
            hours = int(remaining.total_seconds() / 3600) if remaining else 0
            minutes = int((remaining.total_seconds() % 3600) / 60) if remaining else 0
            
            raise AccountLockedError(
                user_id=user_id,
                locked_until=flag.locked_until,
                remaining_time=f"{hours}h {minutes}m"
            )
    
    def get_plan_limit(self, plan_name: str) -> int:
        """Get rate limit based on user's subscription plan."""
        return self._plan_limits.get(plan_name, self._plan_limits["free"])
    
    def reset_user_score(self, user_id: int) -> None:
        """Reset abuse score for a user (admin function)."""
        flag = UserFlag.query.filter_by(user_id=user_id).first()
        if flag:
            flag.abuse_score = 0
            flag.locked_until = None
            db.session.commit()
    
    def _apply_score_decay(self, flag: UserFlag) -> None:
        """Apply time-based decay to abuse score."""
        if not flag.last_updated:
            return
        
        hours_passed = (datetime.utcnow() - flag.last_updated).total_seconds() / 3600
        
        if hours_passed >= self.SCORE_DECAY_HOURS:
            # Reduce score by 1 point for every SCORE_DECAY_HOURS passed
            decay_amount = int(hours_passed / self.SCORE_DECAY_HOURS)
            flag.abuse_score = max(0, flag.abuse_score - decay_amount)
            
            # Auto-unlock if score drops below threshold
            if flag.abuse_score < self.MAX_ABUSE_SCORE and flag.is_locked():
                flag.locked_until = None
    
    def get_user_status(self, user_id: int) -> Dict:
        """Get comprehensive status for a user."""
        flag = UserFlag.query.filter_by(user_id=user_id).first()
        
        if not flag:
            return {
                'user_id': user_id,
                'abuse_score': 0,
                'is_locked': False,
                'remaining_lock_time': None,
                'score_percentage': 0
            }
        
        self._apply_score_decay(flag)
        db.session.commit()
        
        return {
            'user_id': user_id,
            'abuse_score': flag.abuse_score,
            'is_locked': flag.is_locked(),
            'locked_until': flag.locked_until.isoformat() if flag.locked_until else None,
            'remaining_lock_time': flag.remaining_lock_time(),
            'score_percentage': min(100, (flag.abuse_score / self.MAX_ABUSE_SCORE) * 100),
            'last_updated': flag.last_updated.isoformat() if flag.last_updated else None
        }


class AccountLockedError(Exception):
    """Exception raised when a user account is locked."""
    
    def __init__(self, user_id: int, locked_until: datetime, remaining_time: str):
        self.user_id = user_id
        self.locked_until = locked_until
        self.remaining_time = remaining_time
        message = (
            f"Account temporarily locked due to detected abuse patterns. "
            f"Lock expires in {remaining_time}. "
            f"Please contact support if you believe this is an error."
        )
        super().__init__(message)