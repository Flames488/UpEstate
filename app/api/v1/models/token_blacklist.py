# token_blacklist.py
from app.extensions import db
from datetime import datetime

class TokenBlacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), unique=True, nullable=False, index=True)  # Added index
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @classmethod
    def revoke_token(cls, jti):
        """Add a token to the blacklist by its JTI"""
        if not cls.query.filter_by(jti=jti).first():
            revoked_token = cls(jti=jti)
            db.session.add(revoked_token)
            db.session.commit()
    
    @classmethod
    def is_revoked(cls, jti):
        """Check if a token is revoked"""
        return cls.query.filter_by(jti=jti).first() is not None