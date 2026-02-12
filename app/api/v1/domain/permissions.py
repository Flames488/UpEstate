"""
User authorization and role management system.

This module provides a robust system for managing user roles, permissions,
and authorization checks using Python's type system and dataclasses.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Final, Set, ClassVar, NoReturn
from functools import total_ordering


class AuthorizationError(Exception):
    """Base exception for authorization-related errors."""
    
    def __init__(self, message: str, user_id: int | None = None):
        self.message = message
        self.user_id = user_id
        super().__init__(f"{message} (User ID: {user_id})" if user_id else message)


class InsufficientPrivilegesError(AuthorizationError):
    """Raised when a user lacks required privileges."""


class InvalidAccountStateError(AuthorizationError):
    """Raised when an account is in an invalid state for an operation."""


@total_ordering
class UserRole(Enum):
    """Defines all possible user roles in the system with hierarchical ordering."""
    
    USER = auto()
    MODERATOR = auto()
    ADMIN = auto()
    SUPERADMIN = auto()
    
    # Role hierarchy for comparison
    _role_hierarchy: ClassVar[dict['UserRole', int]] = {
        USER: 0,
        MODERATOR: 1,
        ADMIN: 2,
        SUPERADMIN: 3
    }
    
    @property
    def _hierarchy_value(self) -> int:
        """Get the hierarchical value of the role."""
        return self._role_hierarchy[self]
    
    def __lt__(self, other: 'UserRole') -> bool:
        """Compare roles based on hierarchy."""
        if not isinstance(other, UserRole):
            return NotImplemented
        return self._hierarchy_value < other._role_hierarchy[other]
    
    @property
    def has_admin_privileges(self) -> bool:
        """Check if this role has administrative privileges."""
        return self in {UserRole.ADMIN, UserRole.SUPERADMIN}
    
    @property
    def can_moderate(self) -> bool:
        """Check if this role has moderation privileges."""
        return self >= UserRole.MODERATOR
    
    @classmethod
    def from_string(cls, role_str: str) -> 'UserRole':
        """
        Create a UserRole from a string representation.
        
        Args:
            role_str: String representation of the role (case-insensitive)
            
        Returns:
            Corresponding UserRole
            
        Raises:
            ValueError: If the string doesn't match any role
        """
        try:
            return cls[role_str.upper()]
        except KeyError as exc:
            valid_roles = ", ".join(role.name for role in cls)
            raise ValueError(
                f"Invalid role '{role_str}'. Valid roles are: {valid_roles}"
            ) from exc


@dataclass(frozen=True)
class UserContext:
    """
    Immutable context containing user authentication and authorization data.
    
    Attributes:
        user_id: Unique identifier for the user
        role: User's role in the system
        permissions: Set of specific permissions granted to the user
    """
    
    user_id: int
    role: UserRole = UserRole.USER
    permissions: Set[str] = field(default_factory=set, hash=True)
    
    def __post_init__(self) -> None:
        """Validate the user context after initialization."""
        if not isinstance(self.user_id, int) or self.user_id <= 0:
            raise ValueError(f"user_id must be a positive integer, got {self.user_id}")
        if not isinstance(self.role, UserRole):
            raise TypeError(f"role must be an instance of UserRole, got {type(self.role)}")
    
    @property
    def identifier(self) -> str:
        """Get a string identifier for the user."""
        return f"user:{self.user_id}"
    
    def has_permission(self, permission: str) -> bool:
        """Check if the user has a specific permission."""
        return permission in self.permissions
    
    def can(self, permission: str) -> bool:
        """Alias for has_permission for more readable authorization checks."""
        return self.has_permission(permission)


@dataclass(frozen=True)
class AccountState:
    """
    Represents the current state of a user account.
    
    Attributes:
        is_suspended: Whether the account is suspended
        suspension_reason: Reason for suspension, if applicable
        is_email_verified: Whether the user's email is verified
    """
    
    is_suspended: bool = False
    suspension_reason: str | None = None
    is_email_verified: bool = False
    
    @property
    def is_active(self) -> bool:
        """Check if the account is currently active and operational."""
        return not self.is_suspended and self.is_email_verified
    
    @property
    def is_restricted(self) -> bool:
        """Check if the account has any restrictions."""
        return self.is_suspended or not self.is_email_verified


class AuthorizationService:
    """
    Service responsible for authorization checks and permissions.
    
    This service provides static methods for common authorization checks
    and can be extended for more complex authorization logic.
    """
    
    # Admin roles that can bypass ownership checks
    ADMIN_ROLES: Final[Set[UserRole]] = {UserRole.ADMIN, UserRole.SUPERADMIN}
    
    # Roles that can access moderation features
    MODERATION_ROLES: Final[Set[UserRole]] = {UserRole.MODERATOR, *ADMIN_ROLES}
    
    @staticmethod
    def _validate_resource_owner(resource_owner_id: int) -> NoReturn | None:
        """Validate resource owner ID."""
        if not isinstance(resource_owner_id, int) or resource_owner_id <= 0:
            raise ValueError(
                f"resource_owner_id must be a positive integer, got {resource_owner_id}"
            )
    
    @classmethod
    def can_manage_resource(
        cls,
        user: UserContext,
        resource_owner_id: int,
        require_ownership: bool = True
    ) -> bool:
        """
        Check if a user can manage a resource.
        
        Args:
            user: The user attempting the action
            resource_owner_id: The ID of the resource owner
            require_ownership: If True, only owners and admins can manage.
                              If False, moderators can also manage.
        
        Returns:
            True if the user can manage the resource, False otherwise
        """
        cls._validate_resource_owner(resource_owner_id)
        
        # Admins can always manage any resource
        if user.role in cls.ADMIN_ROLES:
            return True
        
        # Moderators can manage if ownership is not strictly required
        if not require_ownership and user.role in cls.MODERATION_ROLES:
            return True
        
        # Users can manage their own resources
        return user.user_id == resource_owner_id
    
    @classmethod
    def require_can_manage_resource(
        cls,
        user: UserContext,
        resource_owner_id: int,
        require_ownership: bool = True
    ) -> None:
        """
        Raise an exception if the user cannot manage the resource.
        
        Args:
            user: The user attempting the action
            resource_owner_id: The ID of the resource owner
            require_ownership: If True, only owners and admins can manage
        
        Raises:
            InsufficientPrivilegesError: If the user cannot manage the resource
        """
        if not cls.can_manage_resource(user, resource_owner_id, require_ownership):
            raise InsufficientPrivilegesError(
                f"User {user.user_id} cannot manage resource owned by {resource_owner_id}",
                user_id=user.user_id
            )
    
    @classmethod
    def can_access_admin_panel(cls, user: UserContext) -> bool:
        """
        Check if a user can access the admin panel.
        
        Args:
            user: The user attempting to access the admin panel
        
        Returns:
            True if the user can access the admin panel, False otherwise
        """
        return user.role.has_admin_privileges
    
    @classmethod
    def can_moderate_content(cls, user: UserContext) -> bool:
        """
        Check if a user can moderate content.
        
        Args:
            user: The user attempting to moderate content
        
        Returns:
            True if the user can moderate content, False otherwise
        """
        return user.role.can_moderate
    
    @staticmethod
    def is_account_eligible_for_action(
        account_state: AccountState,
        require_email_verification: bool = True
    ) -> bool:
        """
        Check if an account is eligible to perform actions.
        
        Args:
            account_state: The current state of the account
            require_email_verification: Whether email verification is required
        
        Returns:
            True if the account is eligible to perform actions
        """
        if account_state.is_suspended:
            return False
        
        if require_email_verification and not account_state.is_email_verified:
            return False
        
        return True
    
    @staticmethod
    def require_account_eligible(
        account_state: AccountState,
        require_email_verification: bool = True
    ) -> None:
        """
        Raise an exception if the account is not eligible for actions.
        
        Args:
            account_state: The current state of the account
            require_email_verification: Whether email verification is required
        
        Raises:
            InvalidAccountStateError: If the account is not eligible
        """
        if not AuthorizationService.is_account_eligible_for_action(
            account_state, require_email_verification
        ):
            reason = "Account is suspended" if account_state.is_suspended else "Email not verified"
            raise InvalidAccountStateError(
                f"Cannot perform action: {reason}",
                user_id=None  # Would need user context to fill this
            )


def main() -> None:
    """Demonstrate usage of the authorization system."""
    # Create user contexts with different roles
    superadmin_user = UserContext(
        user_id=1,
        role=UserRole.SUPERADMIN,
        permissions={"users.delete", "settings.manage"}
    )
    admin_user = UserContext(user_id=2, role=UserRole.ADMIN)
    moderator_user = UserContext(user_id=3, role=UserRole.MODERATOR)
    regular_user = UserContext(user_id=4, role=UserRole.USER)
    
    # Create account states
    active_account = AccountState(is_suspended=False, is_email_verified=True)
    suspended_account = AccountState(is_suspended=True, suspension_reason="Terms violation")
    unverified_account = AccountState(is_suspended=False, is_email_verified=False)
    
    print("=== Authorization System Demo ===\n")
    
    # Test role comparisons
    print("Role Hierarchy Tests:")
    print(f"USER < MODERATOR: {UserRole.USER < UserRole.MODERATOR}")
    print(f"ADMIN >= MODERATOR: {UserRole.ADMIN >= UserRole.MODERATOR}")
    print(f"SUPERADMIN has_admin_privileges: {UserRole.SUPERADMIN.has_admin_privileges}")
    print()
    
    # Test resource management permissions
    print("Resource Management Tests:")
    
    test_cases = [
        (superadmin_user, 999, True, "Superadmin manages other user's resource"),
        (admin_user, 999, True, "Admin manages other user's resource"),
        (regular_user, 4, True, "User manages own resource"),
        (regular_user, 999, False, "User manages other user's resource"),
        (moderator_user, 999, False, "Moderator manages other user's resource (strict)"),
        (moderator_user, 999, True, "Moderator manages other user's resource (lenient)"),
    ]
    
    for user, resource_id, require_ownership, description in test_cases:
        can_manage = AuthorizationService.can_manage_resource(
            user, resource_id, require_ownership
        )
        print(f"  {description}: {can_manage}")
    
    print()
    
    # Test admin panel access
    print("Admin Panel Access Tests:")
    for user in [superadmin_user, admin_user, moderator_user, regular_user]:
        can_access = AuthorizationService.can_access_admin_panel(user)
        print(f"  {user.role.name} can access admin panel: {can_access}")
    
    print()
    
    # Test account eligibility
    print("Account Eligibility Tests:")
    accounts = [
        (active_account, "Active account"),
        (suspended_account, "Suspended account"),
        (unverified_account, "Unverified account"),
    ]
    
    for account, description in accounts:
        is_eligible = AuthorizationService.is_account_eligible_for_action(account)
        print(f"  {description} eligible for action: {is_eligible}")
    
    print()
    
    # Test permission checks
    print("Permission Checks:")
    print(f"  Superadmin has 'users.delete': {superadmin_user.has_permission('users.delete')}")
    print(f"  Superadmin can 'settings.manage': {superadmin_user.can('settings.manage')}")
    print(f"  Admin has 'users.delete': {admin_user.has_permission('users.delete')}")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    main()