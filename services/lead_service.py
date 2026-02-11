
from app.domain.lead_domain import LeadDomain

def create_lead(*, user_id: int, payload: dict):
    LeadDomain.validate_payload(payload)
    return {
        "user_id": user_id,
        "payload": payload,
        "status": "created"
    }
