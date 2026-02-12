from datetime import datetime
from app.extensions import db
from .automation_states import AutomationState

class AutomationJob(db.Model):
    __tablename__ = "automation_jobs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(120), nullable=False)

    state = db.Column(
        db.Enum(AutomationState),
        default=AutomationState.PENDING,
        nullable=False
    )

    attempts = db.Column(db.Integer, default=0)
    last_error = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)