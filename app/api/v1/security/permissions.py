"""
Advanced Permission Management System
Supports MVP mode, granular permissions, and future scalability.
"""

from __future__ import annotations
from functools import wraps
from enum import Enum, auto
from typing import (
    Any, 
    Callable, 
    Dict, 
    FrozenSet, 
    List, 
    Optional, 
    Set, 
    TypeVar, 
    Union,
    cast
)
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
import logging
from contextvars import ContextVar

from app.config.settings import IS_MVP, DEBUG_MODE

# Type aliases
F = TypeVar('F', bound=Callable[..., Any])
R = TypeVar('R')  # Return type

# Context variable for current request's permission context
current_permission_context: ContextVar[Optional[PermissionContext]] = ContextVar(
    'permission_context', default=None
)

# Setup logging
logger = logging.getLogger(__name__)


class PermissionLevel(Enum):
    """Hierarchical permission levels for quick comparisons"""
    NONE = 0
    READ = 1
    WRITE = 2
    DELETE = 3
    ADMIN = 4
    SUPER_ADMIN = 5


class Permission(str, Enum):
    """Granular permission enum with metadata support"""
    
    # Dashboard permissions
    VIEW_DASHBOARD = "dashboard:view"
    EXPORT_DASHBOARD = "dashboard:export"
    
    # Property permissions
    VIEW_PROPERTIES = "properties:view"
    CREATE_PROPERTIES = "properties:create"
    EDIT_PROPERTIES = "properties:edit"
    DELETE_PROPERTIES = "properties:delete"
    MANAGE_PROPERTIES = "properties:manage"
    
    # User permissions
    VIEW_USERS = "users:view"
    CREATE_USERS = "users:create"
    EDIT_USERS = "users:edit"
    DELETE_USERS = "users:delete"
    MANAGE_USERS = "users:manage"
    
    # Billing permissions
    VIEW_BILLING = "billing:view"
    MANAGE_BILLING = "billing:manage"
    EXPORT_BILLING = "billing:export"
    
    # System permissions
    SYSTEM_ADMIN = "system:admin"
    AUDIT_LOG_VIEW = "audit:view"
    
    # Feature flags
    BETA_FEATURES = "features:beta"
    PREMIUM_FEATURES = "features:premium"
    
    @property
    def category(self) -> str:
        """Extract permission category from permission string"""
        return self.value.split(':')[0]
    
    @property
    def action(self) -> str:
        """Extract action from permission string"""
        return self.value.split(':')[1]
    
    @classmethod
    def from_string(cls, permission_str: str) -> Permission:
        """Create Permission enum from string with validation"""
        try:
            return cls(permission_str)
        except ValueError:
            # Try to find case-insensitive match
            for perm in cls:
                if perm.value.lower() == permission_str.lower():
                    return perm
            raise ValueError(f"Invalid permission: {permission_str}")


class Role(str, Enum):
    """System roles with inheritance support"""
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    MANAGER = "manager"
    AGENT = "agent"
    VIEWER = "viewer"
    USER = "user"
    GUEST = "guest"
    
    @property
    def inheritance_chain(self) -> List[Role]:
        """Define role hierarchy for permission inheritance"""
        hierarchy = {
            Role.SUPER_ADMIN: [Role.ADMIN, Role.MANAGER, Role.AGENT, Role.VIEWER, Role.USER, Role.GUEST],
            Role.ADMIN: [Role.MANAGER, Role.AGENT, Role.VIEWER, Role.USER, Role.GUEST],
            Role.MANAGER: [Role.AGENT, Role.VIEWER, Role.USER, Role.GUEST],
            Role.AGENT: [Role.VIEWER, Role.USER, Role.GUEST],
            Role.VIEWER: [Role.GUEST],
            Role.USER: [Role.GUEST],
            Role.GUEST: [],
        }
        return hierarchy.get(self, [])


@dataclass(frozen=True)
class PermissionSet:
    """Immutable collection of permissions with set operations"""
    permissions: FrozenSet[Permission] = field(default_factory=frozenset)
    
    def __contains__(self, permission: Union[Permission, str]) -> bool:
        """Check if permission is in set"""
        if isinstance(permission, str):
            permission = Permission.from_string(permission)
        return permission in self.permissions
    
    def __iter__(self):
        return iter(self.permissions)
    
    def union(self, other: PermissionSet) -> PermissionSet:
        """Combine two permission sets"""
        return PermissionSet(self.permissions.union(other.permissions))
    
    def intersection(self, other: PermissionSet) -> PermissionSet:
        """Find common permissions"""
        return PermissionSet(self.permissions.intersection(other.permissions))
    
    def difference(self, other: PermissionSet) -> PermissionSet:
        """Find permissions in self but not in other"""
        return PermissionSet(self.permissions.difference(other.permissions))
    
    def has_any(self, *permissions: Union[Permission, str]) -> bool:
        """Check if any of the given permissions are present"""
        return any(self._normalize_permission(p) in self.permissions 
                  for p in permissions)
    
    def has_all(self, *permissions: Union[Permission, str]) -> bool:
        """Check if all given permissions are present"""
        return all(self._normalize_permission(p) in self.permissions 
                  for p in permissions)
    
    @staticmethod
    def _normalize_permission(permission: Union[Permission, str]) -> Permission:
        """Convert string to Permission enum if needed"""
        if isinstance(permission, str):
            return Permission.from_string(permission)
        return permission
    
    @classmethod
    def from_list(cls, permissions: List[Union[Permission, str]]) -> PermissionSet:
        """Create PermissionSet from list"""
        normalized = {cls._normalize_permission(p) for p in permissions}
        return cls(frozenset(normalized))


class PermissionRegistry:
    """Central registry for role-permission mappings with caching"""
    
    _instance: Optional[PermissionRegistry] = None
    _role_permissions: Dict[Role, PermissionSet] = {}
    _inheritance_cache: Dict[Role, PermissionSet] = {}
    
    def __new__(cls) -> PermissionRegistry:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize_registry()
        return cls._instance
    
    def _initialize_registry(self) -> None:
        """Initialize the permission registry with role definitions"""
        
        # MVP mode permissions (basic set for all authenticated users)
        mvp_permissions = PermissionSet.from_list([
            Permission.VIEW_DASHBOARD,
            Permission.VIEW_PROPERTIES,
            Permission.CREATE_PROPERTIES,
            Permission.EDIT_PROPERTIES,
        ])
        
        # Production role definitions
        self._role_permissions = {
            Role.SUPER_ADMIN: PermissionSet.from_list([
                Permission.SYSTEM_ADMIN,
                Permission.MANAGE_USERS,
                Permission.MANAGE_BILLING,
                Permission.AUDIT_LOG_VIEW,
            ]),
            Role.ADMIN: PermissionSet.from_list([
                Permission.MANAGE_USERS,
                Permission.MANAGE_PROPERTIES,
                Permission.VIEW_BILLING,
                Permission.MANAGE_BILLING,
                Permission.AUDIT_LOG_VIEW,
            ]),
            Role.MANAGER: PermissionSet.from_list([
                Permission.MANAGE_PROPERTIES,
                Permission.VIEW_BILLING,
                Permission.EXPORT_DASHBOARD,
                Permission.PREMIUM_FEATURES,
            ]),
            Role.AGENT: PermissionSet.from_list([
                Permission.CREATE_PROPERTIES,
                Permission.EDIT_PROPERTIES,
                Permission.VIEW_PROPERTIES,
                Permission.VIEW_DASHBOARD,
                Permission.BETA_FEATURES,
            ]),
            Role.VIEWER: PermissionSet.from_list([
                Permission.VIEW_PROPERTIES,
                Permission.VIEW_DASHBOARD,
            ]),
            Role.USER: PermissionSet.from_list([
                Permission.VIEW_DASHBOARD,
                Permission.VIEW_PROPERTIES,
            ]),
            Role.GUEST: PermissionSet.from_list([
                Permission.VIEW_DASHBOARD,
            ]),
        }
        
        # In MVP mode, all roles get MVP permissions
        if IS_MVP:
            for role in self._role_permissions:
                self._role_permissions[role] = mvp_permissions
    
    def get_permissions(self, role: Union[Role, str], 
                       include_inherited: bool = True) -> PermissionSet:
        """Get permissions for a role, optionally including inherited permissions"""
        if isinstance(role, str):
            role = Role(role)
        
        if not include_inherited:
            return self._role_permissions.get(role, PermissionSet())
        
        # Check cache first
        if role in self._inheritance_cache:
            return self._inheritance_cache[role]
        
        # Calculate inherited permissions
        permissions = self._role_permissions.get(role, PermissionSet())
        
        for inherited_role in role.inheritance_chain:
            permissions = permissions.union(
                self._role_permissions.get(inherited_role, PermissionSet())
            )
        
        # Cache the result
        self._inheritance_cache[role] = permissions
        
        return permissions
    
    def has_permission(self, role: Union[Role, str], 
                      permission: Union[Permission, str]) -> bool:
        """Check if role has specific permission"""
        permissions = self.get_permissions(role)
        return permission in permissions
    
    def add_role_permission(self, role: Union[Role, str], 
                           permission: Union[Permission, str]) -> None:
        """Dynamically add permission to a role (use with caution)"""
        if isinstance(role, str):
            role = Role(role)
        if isinstance(permission, str):
            permission = Permission.from_string(permission)
        
        current = self._role_permissions.get(role, PermissionSet())
        self._role_permissions[role] = current.union(
            PermissionSet.from_list([permission])
        )
        
        # Clear cache for this role and all roles that inherit from it
        self._clear_cache(role)
    
    def _clear_cache(self, role: Role) -> None:
        """Clear inheritance cache for role and its parents"""
        if role in self._inheritance_cache:
            del self._inheritance_cache[role]
        
        # Clear cache for all roles that inherit from this one
        for cached_role in list(self._inheritance_cache.keys()):
            if role in cached_role.inheritance_chain:
                del self._inheritance_cache[cached_role]


@dataclass
class PermissionContext:
    """Context for permission checks within a request"""
    user_id: str
    role: Role
    permissions: PermissionSet
    tenant_id: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def create(cls, user_id: str, role: Union[Role, str], 
               tenant_id: Optional[str] = None, **metadata) -> PermissionContext:
        """Factory method to create permission context"""
        if isinstance(role, str):
            role = Role(role)
        
        registry = PermissionRegistry()
        permissions = registry.get_permissions(role)
        
        return cls(
            user_id=user_id,
            role=role,
            permissions=permissions,
            tenant_id=tenant_id,
            metadata=metadata
        )
    
    def check(self, permission: Union[Permission, str]) -> bool:
        """Check if context has specific permission"""
        return permission in self.permissions
    
    def check_any(self, *permissions: Union[Permission, str]) -> bool:
        """Check if context has any of the given permissions"""
        return self.permissions.has_any(*permissions)
    
    def check_all(self, *permissions: Union[Permission, str]) -> bool:
        """Check if context has all given permissions"""
        return self.permissions.has_all(*permissions)


class PermissionDeniedError(Exception):
    """Raised when permission check fails"""
    def __init__(self, 
                 permission: Union[Permission, str],
                 context: Optional[PermissionContext] = None,
                 message: Optional[str] = None):
        self.permission = permission if isinstance(permission, str) else permission.value
        self.context = context
        self.message = message or f"Permission denied: {self.permission}"
        super().__init__(self.message)


class PermissionManager:
    """Main interface for permission operations"""
    
    def __init__(self):
        self.registry = PermissionRegistry()
        self.logger = logging.getLogger(__name__)
    
    def check_access(self, 
                    role: Union[Role, str],
                    permission: Union[Permission, str],
                    context: Optional[Dict[str, Any]] = None) -> bool:
        """Main permission check with context support"""
        
        # MVP bypass - allow all authenticated users
        if IS_MVP and self._is_authenticated(context):
            self.logger.debug(f"MVP mode: Allowing {permission} for role {role}")
            return True
        
        has_perm = self.registry.has_permission(role, permission)
        
        if not has_perm and DEBUG_MODE:
            self.logger.warning(
                f"Permission denied: {role} lacks {permission}. "
                f"Context: {context}"
            )
        
        return has_perm
    
    def require_permission(self, 
                          permission: Union[Permission, str],
                          context: Optional[PermissionContext] = None) -> bool:
        """Raise exception if permission is not granted"""
        if context is None:
            context = current_permission_context.get()
        
        if context and context.check(permission):
            return True
        
        raise PermissionDeniedError(permission, context)
    
    def get_user_permissions(self, 
                            role: Union[Role, str],
                            include_inherited: bool = True) -> List[str]:
        """Get list of permission strings for a role"""
        permission_set = self.registry.get_permissions(role, include_inherited)
        return [p.value for p in permission_set]
    
    @staticmethod
    def _is_authenticated(context: Optional[Dict[str, Any]]) -> bool:
        """Check if user is authenticated in context"""
        if not context:
            return False
        return context.get('authenticated', False)


# Global permission manager instance
permission_manager = PermissionManager()


# ===== Decorators =====

def require_permission(*permissions: Union[Permission, str]):
    """
    Decorator to require one or more permissions for a function/route.
    
    Usage:
        @require_permission(Permission.VIEW_DASHBOARD)
        @require_permission("dashboard:view", "properties:create")
    """
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Try to get permission context from various sources
            context = _extract_permission_context(args, kwargs)
            
            # MVP bypass
            if IS_MVP and context and context.user_id:
                logger.debug(f"MVP bypass for {func.__name__}")
                return func(*args, **kwargs)
            
            # Check permissions
            if context:
                if len(permissions) == 1:
                    if not context.check(permissions[0]):
                        raise PermissionDeniedError(permissions[0], context)
                else:
                    if not context.check_all(*permissions):
                        raise PermissionDeniedError(
                            f"Multiple permissions required: {permissions}",
                            context
                        )
            else:
                logger.warning(f"No permission context for {func.__name__}")
                # Fallback to basic role check from kwargs
                role = kwargs.get('user_role', Role.GUEST)
                for perm in permissions:
                    if not permission_manager.check_access(role, perm):
                        raise PermissionDeniedError(perm)
            
            return func(*args, **kwargs)
        return cast(F, wrapper)
    return decorator


def require_any_permission(*permissions: Union[Permission, str]):
    """
    Decorator to require at least one of the given permissions.
    """
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            context = _extract_permission_context(args, kwargs)
            
            # MVP bypass
            if IS_MVP and context and context.user_id:
                return func(*args, **kwargs)
            
            if context:
                if not context.check_any(*permissions):
                    raise PermissionDeniedError(
                        f"Requires one of: {permissions}",
                        context
                    )
            else:
                role = kwargs.get('user_role', Role.GUEST)
                has_any = any(
                    permission_manager.check_access(role, perm)
                    for perm in permissions
                )
                if not has_any:
                    raise PermissionDeniedError(f"Requires one of: {permissions}")
            
            return func(*args, **kwargs)
        return cast(F, wrapper)
    return decorator


def permission_context(context: PermissionContext):
    """
    Decorator to set permission context for a block of code.
    
    Usage:
        @permission_context(ctx)
        def sensitive_operation():
            # Code that requires specific permissions
    """
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            token = current_permission_context.set(context)
            try:
                return func(*args, **kwargs)
            finally:
                current_permission_context.reset(token)
        return cast(F, wrapper)
    return decorator


# ===== Helper Functions =====

def _extract_permission_context(args: tuple, kwargs: dict) -> Optional[PermissionContext]:
    """Extract permission context from function arguments"""
    # Check kwargs first
    if 'permission_context' in kwargs:
        return kwargs['permission_context']
    
    # Check args for PermissionContext instance
    for arg in args:
        if isinstance(arg, PermissionContext):
            return arg
    
    # Check for current context
    return current_permission_context.get()


def get_current_permissions() -> List[str]:
    """Get current user's permissions from context"""
    context = current_permission_context.get()
    if context:
        return [p.value for p in context.permissions]
    return []


def has_permission(permission: Union[Permission, str]) -> bool:
    """Quick check if current context has permission"""
    context = current_permission_context.get()
    if context:
        return context.check(permission)
    return False


# ===== Backward Compatibility =====

def has_permission_simple(role: str, permission: str) -> bool:
    """Simple permission check (backward compatibility)"""
    return permission_manager.check_access(role, permission)


def require_permission_simple(permission_name: str):
    """Simple decorator (backward compatibility)"""
    return require_permission(permission_name)


# ===== Example Usage =====
"""
# 1. Using decorators in routes:
@app.route('/admin/users')
@require_permission(Permission.MANAGE_USERS)
def manage_users():
    pass

# 2. Using with context:
context = PermissionContext.create(
    user_id="user123",
    role=Role.ADMIN,
    tenant_id="tenant456"
)

@permission_context(context)
def perform_admin_task():
    if has_permission(Permission.SYSTEM_ADMIN):
        # Do admin stuff
        pass

# 3. Direct permission check:
if permission_manager.check_access(Role.MANAGER, Permission.VIEW_BILLING):
    # Show billing info
    pass

# 4. Multiple permissions:
@require_permission(Permission.VIEW_DASHBOARD, Permission.EXPORT_DASHBOARD)
def export_dashboard_data():
    pass
"""