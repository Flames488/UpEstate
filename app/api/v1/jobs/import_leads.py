# jobs/import_leads.py
from app.services.lead_service import create_lead

def import_job():
    create_lead(
        user_id=1,
        payload={"name": "John", "email": "john@test.com"}
    )
