from app.audit.logger import audit_log

def handle_new_lead(lead, agent):
    lead.assigned_agent_id = agent.id
    audit_log(
        action="AUTO_ASSIGN_AGENT",
        entity="Lead",
        entity_id=lead.id,
        metadata={"agent_id": agent.id}
    )
