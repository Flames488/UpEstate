# feature_flags.py
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, Any, Optional
from app.config.settings import IS_MVP

@dataclass(frozen=True)
class FeatureFlags:
    """Centralized feature flag configuration."""
    enable_signup: bool = True
    enable_payments: bool = True
    enable_automations: bool = True
    enable_webhooks: bool = True
    enable_experimental: bool = False
    enable_analytics: bool = True

    @classmethod
    def from_mvp_mode(cls, is_mvp: bool) -> 'FeatureFlags':
        """Create flags based on MVP mode."""
        if is_mvp:
            return cls(
                enable_signup=True,
                enable_payments=True,
                enable_automations=True,
                enable_webhooks=True,
                enable_experimental=False,
                enable_analytics=True
            )
        # Return default flags for non-MVP mode
        return cls()

    def is_enabled(self, flag_name: str) -> bool:
        """Check if a specific feature flag is enabled."""
        # Convert flag_name to match class attribute naming
        attr_name = flag_name.lower().replace('-', '_')
        
        if hasattr(self, attr_name):
            return getattr(self, attr_name)
        
        # If flag doesn't exist, log warning and return False
        import logging
        logging.warning(f"Unknown feature flag: {flag_name}")
        return False

    def to_dict(self) -> Dict[str, bool]:
        """Convert flags to dictionary for APIs or debugging."""
        return {
            'enable_signup': self.enable_signup,
            'enable_payments': self.enable_payments,
            'enable_automations': self.enable_automations,
            'enable_webhooks': self.enable_webhooks,
            'enable_experimental': self.enable_experimental,
            'enable_analytics': self.enable_analytics,
        }

    @property
    def active_flags(self) -> Dict[str, bool]:
        """Get all active (True) flags."""
        return {k: v for k, v in self.to_dict().items() if v}

    @property
    def inactive_flags(self) -> Dict[str, bool]:
        """Get all inactive (False) flags."""
        return {k: v for k, v in self.to_dict().items() if not v}


@lru_cache(maxsize=1)
def get_global_flags() -> FeatureFlags:
    """Get cached global feature flags instance.
    
    This ensures we only create the flags once and reuse them,
    which is important for performance and consistency.
    """
    return FeatureFlags.from_mvp_mode(IS_MVP)


def is_enabled(flag_name: str, flags_instance: Optional[FeatureFlags] = None) -> bool:
    """Public function to check if a feature is enabled.
    
    Args:
        flag_name: Name of the feature flag to check
        flags_instance: Optional specific flags instance (defaults to global)
    
    Returns:
        bool: True if the feature is enabled
    """
    if flags_instance is None:
        flags_instance = get_global_flags()
    
    return flags_instance.is_enabled(flag_name)


# Global flags instance for backward compatibility
GLOBAL_FLAGS = get_global_flags()