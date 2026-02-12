from app.extensions import db

class UserTenant(db.Model):
    __tablename__ = "user_tenants"

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), primary_key=True)
    role = db.Column(db.String(50), nullable=False)
