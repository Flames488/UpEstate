
from app.config.settings import IS_MVP
import logging

logger = logging.getLogger("audit")

def log_action(action: str, user_id=None, meta=None):
    if IS_MVP:
        logger.info(f"[AUDIT-MVP] {action} user={user_id}")
        return
