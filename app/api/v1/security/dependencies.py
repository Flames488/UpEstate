from fastapi import Depends, HTTPException, status
from app.security.jwt import get_current_user
from app.security.permissions import ROLE_PERMISSIONS, Permission

def require_permissions(required: list[Permission]):
    def checker(user=Depends(get_current_user)):
        user_role = user.role

        if user_role not in ROLE_PERMISSIONS:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid role",
            )

        user_permissions = ROLE_PERMISSIONS[user_role]

        for perm in required:
            if perm not in user_permissions:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing permission: {perm}",
                )

        return user

    return checker
