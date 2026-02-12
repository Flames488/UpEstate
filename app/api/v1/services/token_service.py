from datetime import timedelta
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt,
)
from app.extensions import jwt, db
from app.models.user import User

# Optional blacklist table (recommended for high security)
TOKEN_BLOCKLIST = set()


class TokenService:
    ACCESS_EXPIRES = timedelta(minutes=15)
    REFRESH_EXPIRES = timedelta(days=30)

    @staticmethod
    def generate_tokens(user: User) -> dict:
        additional_claims = {
            "role": user.role,
            "plan": user.subscription_plan
        }

        access_token = create_access_token(
            identity=user.id,
            additional_claims=additional_claims,
            expires_delta=TokenService.ACCESS_EXPIRES,
        )

        refresh_token = create_refresh_token(
            identity=user.id,
            expires_delta=TokenService.REFRESH_EXPIRES,
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

    @staticmethod
    def revoke_token(jti: str):
        TOKEN_BLOCKLIST.add(jti)

    @staticmethod
    def is_token_revoked(jti: str) -> bool:
        return jti in TOKEN_BLOCKLIST


@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    return TokenService.is_token_revoked(jwt_payload["jti"])
