from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy import Column, Integer, DateTime
from sqlalchemy.orm import validates
from extensions import db


class UserFlag(db.Model):
    """Tracks user behavior and implements automatic abuse prevention."""
    
    __tablename__ = 'user_flags'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, unique=True, nullable=False, index=True)
    abuse_score = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    @validates('abuse_score')
    def validate_abuse_score(self, key, score):
        """Ensure abuse score is non-negative."""
        if score < 0:
            raise ValueError("Abuse score cannot be negative")
        return score
    
    def is_locked(self) -> bool:
        """Check if user is currently locked."""
        if not self.locked_until:
            return False
        return self.locked_until > datetime.utcnow()
    
    def remaining_lock_time(self) -> Optional[timedelta]:
        """Get remaining lock duration if locked."""
        if not self.is_locked():
            return None
        return self.locked_until - datetime.utcnow()
    
    def __repr__(self):
        return f'<UserFlag user_id={self.user_id} score={self.abuse_score} locked={self.is_locked()}>'