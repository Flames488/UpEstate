from app.models.lead import Lead
from app.extensions import db

def create_lead(*, user_id: int, payload: dict) -> Lead:
    lead = Lead(
        owner_id=user_id,
        name=payload["name"],
        email=payload["email"],
        phone=payload.get("phone"),
    )

    db.session.add(lead)
    db.session.commit()

    return lead
