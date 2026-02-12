from app.security.domain import automations_allowed, SystemState
from app.feature_flags import GLOBAL_FLAGS


state = SystemState(
billing_enabled=True,
automations_enabled=GLOBAL_FLAGS.enable_automations,
webhooks_enabled=True,
)


if not automations_allowed(state):
raise RuntimeError("Automations disabled by system")