
BLACKLIST = set()

def revoke_token(jti: str):
    BLACKLIST.add(jti)

def is_revoked(jti: str) -> bool:
    return jti in BLACKLIST
