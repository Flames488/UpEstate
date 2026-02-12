PLAN_LIMITS = {
    "free": 10,
    "pro": 1000
}

def check_quota(plan, used):
    limit = PLAN_LIMITS.get(plan, 0)
    if used >= limit:
        raise RuntimeError("Quota exceeded")
