# rbac.py - Professional FastAPI RBAC with multiple patterns
from fastapi import Depends, HTTPException, status
from typing import List, Optional, Callable, Any, Set
from functools import wraps

# Role-based permission definitions using sets for O(1) lookup
ROLE_PERMISSIONS = {
    "admin": {"*"},  # Admin has all permissions
    "agent": {"leads:create", "leads:view"},
    "viewer": {"leads:view"},
    "manager": {"automation:run", "billing:view"},
    "user": {"automation:view"}
}

# Reverse mapping for debugging/auditing
PERMISSION_ROLES = {}
for role, perms in ROLE_PERMISSIONS.items():
    for perm in perms:
        if perm not in PERMISSION_ROLES:
            PERMISSION_ROLES[perm] = []
        PERMISSION_ROLES[perm].append(role)

# Assuming you have a get_current_user dependency
# This should be defined in your auth/jwt.py file
try:
    from auth.jwt import get_current_user, get_current_user_claims
except ImportError:
    # Placeholder implementations for demonstration
    def get_current_user():
        """Placeholder - implement this in your auth system"""
        raise NotImplementedError("get_current_user must be implemented")
    
    def get_current_user_claims():
        """Placeholder - implement this to get JWT claims directly"""
        raise NotImplementedError("get_current_user_claims must be implemented")


# ==================== CORE PERMISSION CHECKING ====================

def has_permission(role: str, permission: str) -> bool:
    """
    Check if a role has a specific permission.
    
    Args:
        role: User role (admin, agent, viewer, manager, user)
        permission: Permission string to check (e.g., "leads:view")
    
    Returns:
        bool: True if role has permission, False otherwise
    """
    permissions = ROLE_PERMISSIONS.get(role, set())
    return "*" in permissions or permission in permissions


def check_permission_for_user(user, permission: str) -> bool:
    """
    Check if a user object has a specific permission.
    
    Args:
        user: User object with role and is_admin attributes
        permission: Permission string to check
    
    Returns:
        bool: True if user has permission, False otherwise
    """
    # Check if user is admin (has all permissions)
    if getattr(user, 'is_admin', False):
        return True
    
    # Check role-based permissions
    user_role = getattr(user, 'role', None)
    if not user_role:
        return False
    
    return has_permission(user_role, permission)


# ==================== DEPENDENCY INJECTION PATTERN (FastAPI Native) ====================

def permission_required(permission: str):
    """
    FastAPI dependency for permission checking.
    Use as: user = Depends(permission_required("leads:view"))
    
    Args:
        permission: Permission string required for the endpoint
    """
    def permission_checker(current_user = Depends(get_current_user)):
        if not check_permission_for_user(current_user, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required. Your role: {getattr(current_user, 'role', 'unknown')}"
            )
        return current_user
    return permission_checker


def admin_required(current_user = Depends(get_current_user)):
    """
    FastAPI dependency to check if current user is an admin.
    """
    if not getattr(current_user, 'is_admin', False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user


def role_required(allowed_roles: List[str]):
    """
    FastAPI dependency to check if current user has one of the allowed roles.
    
    Args:
        allowed_roles: List of role names that are allowed
    """
    def role_checker(current_user = Depends(get_current_user)):
        user_role = getattr(current_user, 'role', None)
        
        if not user_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User role not found"
            )
        
        if user_role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role required: {', '.join(allowed_roles)}. Your role: {user_role}"
            )
        return current_user
    return role_checker


# ==================== DECORATOR PATTERN (Flask-style) ====================

def require_permission(permission: str):
    """
    Decorator for permission checking (Flask-style pattern).
    Use as: @require_permission("leads:view")
    
    Note: This works with FastAPI but requires careful handling.
    Best for simple functions or class-based views.
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Try to get user from different possible sources
            user = None
            
            # Check if user is in kwargs (FastAPI dependency injection)
            if 'user' in kwargs:
                user = kwargs['user']
            elif 'current_user' in kwargs:
                user = kwargs['current_user']
            
            # If not found, try to get from get_current_user dependency
            if user is None:
                try:
                    user = await get_current_user()
                except:
                    # If that fails, check for JWT claims directly
                    try:
                        claims = await get_current_user_claims()
                        # Create a mock user object from claims
                        class MockUser:
                            def __init__(self, claims):
                                self.role = claims.get('role')
                                self.is_admin = claims.get('role') == 'admin'
                        user = MockUser(claims)
                    except:
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Could not authenticate user"
                        )
            
            # Check permission
            if not check_permission_for_user(user, permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission '{permission}' denied"
                )
            
            return await func(*args, **kwargs) if callable(getattr(func, '__await__', None)) else func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_role(allowed_roles: List[str]):
    """
    Decorator for role checking (Flask-style pattern).
    Use as: @require_role(["admin", "manager"])
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            user = None
            
            # Similar user extraction logic as above
            if 'user' in kwargs:
                user = kwargs['user']
            elif 'current_user' in kwargs:
                user = kwargs['current_user']
            
            if user is None:
                try:
                    user = await get_current_user()
                except:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication required"
                    )
            
            user_role = getattr(user, 'role', None)
            if not user_role or user_role not in allowed_roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Required roles: {', '.join(allowed_roles)}"
                )
            
            return await func(*args, **kwargs) if callable(getattr(func, '__await__', None)) else func(*args, **kwargs)
        
        return wrapper
    return decorator


# ==================== UTILITY FUNCTIONS ====================

def get_roles_with_permission(permission: str) -> List[str]:
    """
    Get all roles that have a specific permission.
    Useful for auditing and debugging.
    """
    return PERMISSION_ROLES.get(permission, [])


def get_all_permissions() -> Set[str]:
    """
    Get all unique permissions across all roles.
    """
    all_perms = set()
    for perms in ROLE_PERMISSIONS.values():
        all_perms.update(perms)
    return all_perms - {"*"}  # Exclude wildcard


def add_permission_to_role(role: str, permission: str):
    """
    Dynamically add a permission to a role.
    Use with caution in production.
    """
    if role not in ROLE_PERMISSIONS:
        ROLE_PERMISSIONS[role] = set()
    ROLE_PERMISSIONS[role].add(permission)
    
    # Update reverse mapping
    if permission not in PERMISSION_ROLES:
        PERMISSION_ROLES[permission] = []
    if role not in PERMISSION_ROLES[permission]:
        PERMISSION_ROLES[permission].append(role)


# ==================== EXAMPLE USAGE ====================

class ExampleUser:
    """Example user class for demonstration"""
    def __init__(self, username: str, role: str, is_admin: bool = False):
        self.username = username
        self.role = role
        self.is_admin = is_admin
        self.email = f"{username}@example.com"


# Example of different usage patterns:

"""
# Pattern 1: FastAPI Dependency Injection (Recommended)
from fastapi import APIRouter, Depends
from .rbac import permission_required, admin_required, role_required

router = APIRouter()

@router.get("/leads")
async def get_leads(user = Depends(permission_required("leads:view"))):
    return {"message": "Leads data", "user": user.username}

@router.post("/leads")
async def create_lead(user = Depends(permission_required("leads:create"))):
    return {"message": "Lead created"}

@router.get("/admin/stats")
async def get_stats(user = Depends(admin_required)):
    return {"message": "Admin stats"}


# Pattern 2: Decorator Pattern
from .rbac import require_permission, require_role

@router.get("/automation")
@require_permission("automation:view")
async def view_automation(user: ExampleUser):  # user should be injected by your auth middleware
    return {"message": "Automation data"}

@router.post("/automation/run")
@require_role(["admin", "manager"])
async def run_automation(user: ExampleUser):
    return {"message": "Automation running"}


# Pattern 3: Programmatic checking
from .rbac import has_permission, check_permission_for_user

@router.get("/check-permission/{role}/{permission}")
async def check_permission(role: str, permission: str):
    has_perm = has_permission(role, permission)
    return {
        "role": role,
        "permission": permission,
        "has_permission": has_perm,
        "roles_with_permission": get_roles_with_permission(permission)
    }
"""


# ==================== TESTING HELPERS ====================

def create_test_user(role: str = "user", is_admin: bool = False) -> ExampleUser:
    """Helper to create test users for development"""
    return ExampleUser(
        username=f"test_{role}",
        role=role,
        is_admin=is_admin or role == "admin"
    )


if __name__ == "__main__":
    # Quick tests
    print("RBAC System Test")
    print("=" * 50)
    
    test_cases = [
        ("admin", "leads:view", True),
        ("admin", "anything:here", True),
        ("agent", "leads:view", True),
        ("agent", "leads:create", True),
        ("agent", "automation:view", False),
        ("viewer", "leads:view", True),
        ("viewer", "leads:create", False),
        ("manager", "automation:run", True),
        ("manager", "billing:view", True),
        ("user", "automation:view", True),
        ("user", "automation:run", False),
    ]
    
    for role, perm, expected in test_cases:
        result = has_permission(role, perm)
        status = "✓" if result == expected else "✗"
        print(f"{status} {role:10} -> {perm:20} = {result:5} (expected: {expected})")