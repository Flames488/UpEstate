from app.config.settings import IS_MVP

def is_enabled(flag_name: str) -> bool:
    if IS_MVP:
        return True  # Everything ON in MVP
    # Future: real feature flag logic
    return False