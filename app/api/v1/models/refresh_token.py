from datetime import datetime
from app.extensions import db


class RefreshToken(db.Model):
id = db.Column(db.Integer, primary_key=True)
user_id = db.Column(db.Integer, nullable=False, index=True)
token_hash = db.Column(db.String(255), nullable=False, unique=True)
revoked = db.Column(db.Boolean, default=False)
created_at = db.Column(db.DateTime, default=datetime.utcnow)
expires_at = db.Column(db.DateTime, nullable=False)