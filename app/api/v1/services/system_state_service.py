"""System state loader for feature flag management."""

from typing import Final
from app.models.system_flag import SystemFlag
from app.security.domain import SystemState
import logging

logger = logging.getLogger(__name__)

# Default system state configuration
_DEFAULT_SYSTEM_STATE: Final[SystemState] = SystemState(
    billing_enabled=True,
    automations_enabled=True,
    webhooks_enabled=True,
)

# Feature flag keys mapping
_FEATURE_FLAGS: Final[dict[str, str]] = {
    "billing": "billing_enabled",
    "automations": "automations_enabled",
    "webhooks": "webhooks_enabled",
}


def load_system_state() -> SystemState:
    """
    Load the current system state from persisted feature flags.
    
    Returns:
        SystemState: Current system configuration with feature flags applied.
    
    Raises:
        DatabaseError: If there's an issue querying the database.
    """
    try:
        flags = _fetch_system_flags()
        return _build_system_state(flags)
    except Exception as e:
        logger.error("Failed to load system state: %s", e, exc_info=True)
        # Return default state on failure to ensure system remains operational
        return _DEFAULT_SYSTEM_STATE


def _fetch_system_flags() -> dict[str, bool]:
    """Retrieve all system flags from the database."""
    try:
        all_flags = SystemFlag.query.all()
        return {flag.key: flag.enabled for flag in all_flags}
    except Exception as e:
        logger.warning("Failed to fetch system flags, using defaults: %s", e)
        return {}


def _build_system_state(flags: dict[str, bool]) -> SystemState:
    """Construct SystemState from fetched flags with fallback to defaults."""
    
    # Start with default values
    state_args = {
        "billing_enabled": _DEFAULT_SYSTEM_STATE.billing_enabled,
        "automations_enabled": _DEFAULT_SYSTEM_STATE.automations_enabled,
        "webhooks_enabled": _DEFAULT_SYSTEM_STATE.webhooks_enabled,
    }
    
    # Override with actual flag values if they exist
    for flag_key, state_key in _FEATURE_FLAGS.items():
        if flag_key in flags:
            state_args[state_key] = flags[flag_key]
    
    return SystemState(**state_args)