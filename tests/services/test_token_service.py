from app.services.token_service import (
    revoke_token,
    is_token_revoked
)

def test_token_revocation(db_session):
    fake_jti = "123e4567-e89b-12d3-a456-426614174000"

    revoke_token(fake_jti)

    assert is_token_revoked(fake_jti) is True


def test_non_revoked_token_returns_false():
    assert is_token_revoked("non-existent-jti") is False
