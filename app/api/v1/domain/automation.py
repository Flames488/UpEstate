from dataclasses import dataclass


@dataclass(frozen=True)
class AutomationContext:
    enabled: bool
    failure_rate: float
    executions_today: int
    daily_limit: int


def can_execute(ctx: AutomationContext) -> bool:
    if not ctx.enabled:
        return False

    if ctx.failure_rate > 0.3:
        return False

    if ctx.executions_today >= ctx.daily_limit:
        return False

    return True