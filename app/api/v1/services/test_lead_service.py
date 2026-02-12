from app.services.lead_service import create_lead

def test_create_lead(db_session):
    lead = create_lead(
        user_id=1,
        payload={
            "name": "Jane",
            "email": "jane@test.com"
        }
    )

    assert lead.id is not None
    assert lead.owner_id == 1
