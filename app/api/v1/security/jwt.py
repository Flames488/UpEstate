def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_jwt(token)

    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    return UserContext(
        id=payload["sub"],
        role=payload["role"],
        tenant_id=payload["tenant_id"],
        plan=payload["plan"],
    )
