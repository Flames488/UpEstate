from app.extensions import db
from app.billing.models import Payment

def is_idempotent(reference):
    return not db.session.query(Payment.id).filter_by(reference=reference).first()
