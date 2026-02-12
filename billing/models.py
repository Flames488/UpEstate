
from datetime import datetime

class Subscription:
    def __init__(self, user_id, plan):
        self.user_id = user_id
        self.plan = plan
        self.started_at = datetime.utcnow()
