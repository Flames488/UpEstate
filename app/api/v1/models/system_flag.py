from app.extensions import db

class SystemFlag(db.Model):
key = db.Column(db.String(50), primary_key=True)
enabled = db.Column(db.Boolean, default=True)