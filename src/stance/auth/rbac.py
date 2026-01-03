"""
Role-Based Access Control (RBAC) for Mantissa Stance.

Provides role and permission management for authorization.

Part of Phase 92: API Gateway & Authentication
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from stance.auth.models import User, UserRole


# =============================================================================
# Exceptions
# =============================================================================

class RBACError(Exception):
    """Base RBAC error."""
    pass


class PermissionDeniedError(RBACError):
    """Permission denied."""
    pass


class RoleNotFoundError(RBACError):
    """Role not found."""
    pass


# =============================================================================
# Permission Model
# =============================================================================

@dataclass
class Permission:
    """
    Permission definition.

    Permissions follow the pattern: resource:action
    Examples: findings:read, assets:write, reports:generate
    """
    id: str
    resource: str
    action: str
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            self.id = f"{self.resource}:{self.action}"

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if isinstance(other, Permission):
            return self.id == other.id
        return False

    def matches(self, resource: str, action: str) -> bool:
        """
        Check if permission matches resource and action.

        Supports wildcards: * matches any
        """
        resource_match = self.resource == "*" or self.resource == resource
        action_match = self.action == "*" or self.action == action
        return resource_match and action_match

    @classmethod
    def from_string(cls, permission_str: str) -> "Permission":
        """Create from string like 'resource:action'."""
        parts = permission_str.split(":", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid permission format: {permission_str}")
        return cls(id=permission_str, resource=parts[0], action=parts[1])


# =============================================================================
# Role Model
# =============================================================================

@dataclass
class Role:
    """
    Role definition.

    A role is a collection of permissions that can be assigned to users.
    """
    id: str
    name: str
    description: str = ""
    permissions: Set[str] = field(default_factory=set)
    inherits_from: List[str] = field(default_factory=list)
    is_system_role: bool = False
    is_default: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if isinstance(self.permissions, list):
            self.permissions = set(self.permissions)

    def has_permission(self, permission: str) -> bool:
        """Check if role has a specific permission."""
        if "*:*" in self.permissions:
            return True
        if permission in self.permissions:
            return True
        # Check wildcards
        resource = permission.split(":")[0] if ":" in permission else permission
        if f"{resource}:*" in self.permissions:
            return True
        if f"*:{permission.split(':')[1]}" in self.permissions:
            return True
        return False

    def add_permission(self, permission: str) -> None:
        """Add a permission to the role."""
        self.permissions.add(permission)

    def remove_permission(self, permission: str) -> None:
        """Remove a permission from the role."""
        self.permissions.discard(permission)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "permissions": list(self.permissions),
            "inherits_from": self.inherits_from,
            "is_system_role": self.is_system_role,
            "is_default": self.is_default,
        }


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class RBACConfig:
    """
    RBAC configuration.

    Attributes:
        default_role: Default role for new users
        super_admin_bypass: Super admins bypass all permission checks
        cache_permissions: Cache resolved permissions
        audit_access_checks: Log access check results
    """
    default_role: str = "viewer"
    super_admin_bypass: bool = True
    cache_permissions: bool = True
    audit_access_checks: bool = False


# =============================================================================
# RBAC Manager
# =============================================================================

class RBACManager:
    """
    Role-Based Access Control manager.

    Handles role management and permission checking.
    """

    def __init__(self, config: Optional[RBACConfig] = None):
        """
        Initialize RBAC manager.

        Args:
            config: RBAC configuration
        """
        self.config = config or RBACConfig()
        self._roles: Dict[str, Role] = {}
        self._permissions: Dict[str, Permission] = {}
        self._permission_cache: Dict[str, Set[str]] = {}

        # Initialize default roles and permissions
        self._init_default_permissions()
        self._init_default_roles()

    def _init_default_permissions(self) -> None:
        """Initialize default system permissions."""
        default_permissions = [
            # Findings
            ("findings:read", "findings", "read", "View security findings"),
            ("findings:write", "findings", "write", "Create/update findings"),
            ("findings:delete", "findings", "delete", "Delete findings"),
            ("findings:export", "findings", "export", "Export findings"),
            # Assets
            ("assets:read", "assets", "read", "View assets"),
            ("assets:write", "assets", "write", "Manage assets"),
            ("assets:delete", "assets", "delete", "Delete assets"),
            # Scans
            ("scans:read", "scans", "read", "View scan results"),
            ("scans:run", "scans", "run", "Run scans"),
            ("scans:schedule", "scans", "schedule", "Schedule scans"),
            ("scans:delete", "scans", "delete", "Delete scan data"),
            # Policies
            ("policies:read", "policies", "read", "View policies"),
            ("policies:write", "policies", "write", "Create/update policies"),
            ("policies:delete", "policies", "delete", "Delete policies"),
            ("policies:enable", "policies", "enable", "Enable/disable policies"),
            # Reports
            ("reports:read", "reports", "read", "View reports"),
            ("reports:generate", "reports", "generate", "Generate reports"),
            ("reports:schedule", "reports", "schedule", "Schedule reports"),
            ("reports:delete", "reports", "delete", "Delete reports"),
            # Dashboards
            ("dashboards:read", "dashboards", "read", "View dashboards"),
            ("dashboards:write", "dashboards", "write", "Create/update dashboards"),
            ("dashboards:delete", "dashboards", "delete", "Delete dashboards"),
            # Compliance
            ("compliance:read", "compliance", "read", "View compliance status"),
            ("compliance:export", "compliance", "export", "Export compliance reports"),
            # Settings
            ("settings:read", "settings", "read", "View settings"),
            ("settings:write", "settings", "write", "Modify settings"),
            # Users (admin)
            ("users:read", "users", "read", "View users"),
            ("users:write", "users", "write", "Manage users"),
            ("users:delete", "users", "delete", "Delete users"),
            # API Keys
            ("apikeys:read", "apikeys", "read", "View API keys"),
            ("apikeys:create", "apikeys", "create", "Create API keys"),
            ("apikeys:revoke", "apikeys", "revoke", "Revoke API keys"),
            # Tenants (super admin)
            ("tenants:read", "tenants", "read", "View tenants"),
            ("tenants:write", "tenants", "write", "Manage tenants"),
            ("tenants:delete", "tenants", "delete", "Delete tenants"),
            # Admin
            ("admin:*", "admin", "*", "Full admin access"),
        ]

        for perm_id, resource, action, description in default_permissions:
            self._permissions[perm_id] = Permission(
                id=perm_id,
                resource=resource,
                action=action,
                description=description,
            )

    def _init_default_roles(self) -> None:
        """Initialize default system roles."""
        default_roles = get_default_roles()
        for role in default_roles:
            self._roles[role.id] = role

    def get_role(self, role_id: str) -> Optional[Role]:
        """Get a role by ID."""
        return self._roles.get(role_id)

    def list_roles(self, include_system: bool = True) -> List[Role]:
        """List all roles."""
        if include_system:
            return list(self._roles.values())
        return [r for r in self._roles.values() if not r.is_system_role]

    def create_role(
        self,
        role_id: str,
        name: str,
        description: str = "",
        permissions: Optional[List[str]] = None,
        inherits_from: Optional[List[str]] = None,
    ) -> Role:
        """
        Create a new role.

        Args:
            role_id: Unique role ID
            name: Display name
            description: Role description
            permissions: List of permission strings
            inherits_from: List of role IDs to inherit from

        Returns:
            Created Role
        """
        if role_id in self._roles:
            raise RBACError(f"Role already exists: {role_id}")

        role = Role(
            id=role_id,
            name=name,
            description=description,
            permissions=set(permissions or []),
            inherits_from=inherits_from or [],
        )
        self._roles[role_id] = role
        return role

    def update_role(
        self,
        role_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        permissions: Optional[List[str]] = None,
    ) -> Role:
        """Update an existing role."""
        role = self._roles.get(role_id)
        if role is None:
            raise RoleNotFoundError(f"Role not found: {role_id}")

        if role.is_system_role:
            raise RBACError("Cannot modify system roles")

        if name is not None:
            role.name = name
        if description is not None:
            role.description = description
        if permissions is not None:
            role.permissions = set(permissions)

        # Clear cache
        self._permission_cache.clear()

        return role

    def delete_role(self, role_id: str) -> bool:
        """Delete a role."""
        role = self._roles.get(role_id)
        if role is None:
            return False

        if role.is_system_role:
            raise RBACError("Cannot delete system roles")

        del self._roles[role_id]
        self._permission_cache.clear()
        return True

    def get_role_permissions(self, role_id: str, resolve_inheritance: bool = True) -> Set[str]:
        """
        Get all permissions for a role.

        Args:
            role_id: Role ID
            resolve_inheritance: Include inherited permissions

        Returns:
            Set of permission strings
        """
        # Check cache
        cache_key = f"{role_id}:{resolve_inheritance}"
        if self.config.cache_permissions and cache_key in self._permission_cache:
            return self._permission_cache[cache_key].copy()

        role = self._roles.get(role_id)
        if role is None:
            return set()

        permissions = role.permissions.copy()

        if resolve_inheritance:
            for parent_id in role.inherits_from:
                parent_perms = self.get_role_permissions(parent_id, resolve_inheritance=True)
                permissions.update(parent_perms)

        # Cache result
        if self.config.cache_permissions:
            self._permission_cache[cache_key] = permissions.copy()

        return permissions

    def get_user_permissions(self, user: User) -> Set[str]:
        """Get all permissions for a user."""
        permissions = user.permissions.copy()

        # Add permissions from built-in roles
        for role in user.roles:
            role_obj = self._roles.get(role.value)
            if role_obj:
                permissions.update(self.get_role_permissions(role_obj.id))

        # Add permissions from custom roles
        for role_id in user.custom_roles:
            permissions.update(self.get_role_permissions(role_id))

        return permissions

    def check_permission(
        self,
        user: User,
        permission: str,
        resource_id: Optional[str] = None,
    ) -> bool:
        """
        Check if user has a permission.

        Args:
            user: User to check
            permission: Permission string (e.g., "findings:read")
            resource_id: Optional specific resource ID

        Returns:
            True if permitted
        """
        # Super admin bypass
        if self.config.super_admin_bypass and user.is_super_admin():
            return True

        # Check user's permissions
        user_perms = self.get_user_permissions(user)

        # Check exact match
        if permission in user_perms:
            return True

        # Check wildcards
        if "*:*" in user_perms:
            return True

        parts = permission.split(":", 1)
        if len(parts) == 2:
            resource, action = parts
            if f"{resource}:*" in user_perms:
                return True
            if f"*:{action}" in user_perms:
                return True

        return False

    def require_permission(
        self,
        user: User,
        permission: str,
        resource_id: Optional[str] = None,
    ) -> None:
        """
        Require a permission or raise exception.

        Args:
            user: User to check
            permission: Required permission
            resource_id: Optional specific resource ID

        Raises:
            PermissionDeniedError: If permission denied
        """
        if not self.check_permission(user, permission, resource_id):
            raise PermissionDeniedError(
                f"Permission denied: {permission} for user {user.id}"
            )

    def check_any_permission(self, user: User, permissions: List[str]) -> bool:
        """Check if user has any of the permissions."""
        return any(self.check_permission(user, p) for p in permissions)

    def check_all_permissions(self, user: User, permissions: List[str]) -> bool:
        """Check if user has all of the permissions."""
        return all(self.check_permission(user, p) for p in permissions)

    def list_permissions(self) -> List[Permission]:
        """List all defined permissions."""
        return list(self._permissions.values())

    def get_stats(self) -> Dict[str, Any]:
        """Get RBAC statistics."""
        return {
            "total_roles": len(self._roles),
            "system_roles": sum(1 for r in self._roles.values() if r.is_system_role),
            "custom_roles": sum(1 for r in self._roles.values() if not r.is_system_role),
            "total_permissions": len(self._permissions),
            "cache_size": len(self._permission_cache),
        }


# =============================================================================
# Default Roles
# =============================================================================

def get_default_roles() -> List[Role]:
    """Get default system roles."""
    return [
        Role(
            id="super_admin",
            name="Super Administrator",
            description="Full system access across all tenants",
            permissions={"*:*"},
            is_system_role=True,
        ),
        Role(
            id="admin",
            name="Administrator",
            description="Full access within tenant",
            permissions={
                "findings:*", "assets:*", "scans:*", "policies:*",
                "reports:*", "dashboards:*", "compliance:*",
                "settings:*", "users:*", "apikeys:*",
            },
            is_system_role=True,
        ),
        Role(
            id="security_analyst",
            name="Security Analyst",
            description="View and analyze security data",
            permissions={
                "findings:read", "findings:export",
                "assets:read",
                "scans:read", "scans:run",
                "policies:read",
                "reports:read", "reports:generate",
                "dashboards:read",
                "compliance:read", "compliance:export",
            },
            is_system_role=True,
        ),
        Role(
            id="security_engineer",
            name="Security Engineer",
            description="Manage security configurations",
            permissions={
                "findings:read", "findings:write", "findings:export",
                "assets:read", "assets:write",
                "scans:read", "scans:run", "scans:schedule",
                "policies:read", "policies:write", "policies:enable",
                "reports:read", "reports:generate", "reports:schedule",
                "dashboards:read", "dashboards:write",
                "compliance:read", "compliance:export",
                "apikeys:read", "apikeys:create",
            },
            is_system_role=True,
        ),
        Role(
            id="compliance_officer",
            name="Compliance Officer",
            description="Compliance monitoring and reporting",
            permissions={
                "findings:read", "findings:export",
                "assets:read",
                "scans:read",
                "policies:read",
                "reports:read", "reports:generate",
                "dashboards:read",
                "compliance:read", "compliance:export",
            },
            is_system_role=True,
        ),
        Role(
            id="auditor",
            name="Auditor",
            description="Read-only access for auditing",
            permissions={
                "findings:read",
                "assets:read",
                "scans:read",
                "policies:read",
                "reports:read",
                "dashboards:read",
                "compliance:read",
                "settings:read",
            },
            is_system_role=True,
        ),
        Role(
            id="viewer",
            name="Viewer",
            description="Basic read-only access",
            permissions={
                "findings:read",
                "assets:read",
                "dashboards:read",
                "compliance:read",
            },
            is_system_role=True,
            is_default=True,
        ),
        Role(
            id="api_service",
            name="API Service",
            description="Service account for API access",
            permissions={
                "findings:read", "findings:write",
                "assets:read", "assets:write",
                "scans:read", "scans:run",
            },
            is_system_role=True,
        ),
    ]


def create_rbac_manager(
    super_admin_bypass: bool = True,
    cache_permissions: bool = True,
) -> RBACManager:
    """Factory function to create RBAC manager."""
    config = RBACConfig(
        super_admin_bypass=super_admin_bypass,
        cache_permissions=cache_permissions,
    )
    return RBACManager(config)
