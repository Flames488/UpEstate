
class LeadDomain:
    @staticmethod
    def validate_payload(payload: dict):
        if "email" not in payload:
            raise ValueError("Lead email is required")
