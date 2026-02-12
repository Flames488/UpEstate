from pydantic import BaseSettings


class FeatureFlags(BaseSettings):
    ENABLE_STRIPE: bool = False
    ENABLE_PAYSTACK: bool = True

    class Config:
        env_prefix = "FEATURE_"
        case_sensitive = True


feature_flags = FeatureFlags()
