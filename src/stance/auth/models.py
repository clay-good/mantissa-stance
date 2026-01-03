"""
Authentication data models for Mantissa Stance.

Provides data structures for users, API keys, tokens, sessions, and audit events.

Part of Phase 92: API Gateway & Authentication
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set


# =============================================================================
# Enums
# =============================================================================

class AuthMethod(Enum):
    """Authentication methods supported."""
    NONE = "none"
    JWT = "jwt"
    API_KEY = "api_key"
    BASIC = "basic"
    OAUTH2 = "oauth2"
    OIDC = "oidc"
    SESSION = "session"
    MTLS = "mtls"


class UserStatus(Enum):
    """User account status."""
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DISABLED = "disabled"
    LOCKED = "locked"
    DELETED = "deleted"


class UserRole(Enum):
    """Built-in user roles."""
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    SECURITY_ENGINEER = "security_engineer"
    COMPLIANCE_OFFICER = "compliance_officer"
    AUDITOR = "auditor"
    VIEWER = "viewer"
    API_SERVICE = "api_service"


class APIKeyStatus(Enum):
    """API key status."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    DISABLED = "disabled"


class TokenType(Enum):
    """Token types."""
    ACCESS = "access"
    REFRESH = "refresh"
    API_KEY = "api_key"
    SERVICE = "service"
    IMPERSONATION = "impersonation"


class AuditEventType(Enum):
    """Authentication audit event types."""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    TOKEN_ISSUED = "token_issued"
    TOKEN_REFRESHED = "token_refreshed"
    TOKEN_REVOKED = "token_revoked"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_INVALID = "token_invalid"
    API_KEY_CREATED = "api_key_created"
    API_KEY_USED = "api_key_used"
    API_KEY_REVOKED = "api_key_revoked"
    API_KEY_EXPIRED = "api_key_expired"
    PASSWORD_CHANGED = "password_changed"
    PASSWORD_RESET = "password_reset"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    MFA_CHALLENGE = "mfa_challenge"
    MFA_SUCCESS = "mfa_success"
    MFA_FAILURE = "mfa_failure"
    SESSION_CREATED = "session_created"
    SESSION_EXPIRED = "session_expired"
    SESSION_TERMINATED = "session_terminated"
    PERMISSION_DENIED = "permission_denied"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REMOVED = "role_removed"
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    USER_LOCKED = "user_locked"
    USER_UNLOCKED = "user_unlocked"
    OAUTH_CALLBACK = "oauth_callback"
    IMPERSONATION_START = "impersonation_start"
    IMPERSONATION_END = "impersonation_end"


# =============================================================================
# User Models
# =============================================================================

@dataclass
class UserCredentials:
    """
    User credential storage.

    Stores hashed password and MFA settings.
    """
    password_hash: str
    password_salt: str
    password_algorithm: str = "pbkdf2_sha256"
    password_iterations: int = 100000
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    mfa_backup_codes: List[str] = field(default_factory=list)
    last_password_change: Optional[datetime] = None
    password_expires_at: Optional[datetime] = None
    failed_login_attempts: int = 0
    last_failed_login: Optional[datetime] = None
    lockout_until: Optional[datetime] = None

    @classmethod
    def create(cls, password: str) -> "UserCredentials":
        """Create credentials from plaintext password."""
        salt = secrets.token_hex(32)
        password_hash = cls._hash_password(password, salt)
        return cls(
            password_hash=password_hash,
            password_salt=salt,
            last_password_change=datetime.utcnow(),
        )

    @staticmethod
    def _hash_password(password: str, salt: str, iterations: int = 100000) -> str:
        """Hash password using PBKDF2-SHA256."""
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        ).hex()

    def verify_password(self, password: str) -> bool:
        """Verify a password against stored hash."""
        computed_hash = self._hash_password(
            password,
            self.password_salt,
            self.password_iterations,
        )
        return secrets.compare_digest(computed_hash, self.password_hash)

    def update_password(self, new_password: str) -> None:
        """Update to a new password."""
        self.password_salt = secrets.token_hex(32)
        self.password_hash = self._hash_password(new_password, self.password_salt)
        self.last_password_change = datetime.utcnow()
        self.failed_login_attempts = 0

    def record_failed_login(self, lockout_threshold: int = 5, lockout_duration: int = 900) -> bool:
        """
        Record a failed login attempt.

        Returns True if account is now locked.
        """
        self.failed_login_attempts += 1
        self.last_failed_login = datetime.utcnow()
        if self.failed_login_attempts >= lockout_threshold:
            self.lockout_until = datetime.utcnow() + timedelta(seconds=lockout_duration)
            return True
        return False

    def is_locked(self) -> bool:
        """Check if account is currently locked."""
        if self.lockout_until is None:
            return False
        if datetime.utcnow() >= self.lockout_until:
            self.lockout_until = None
            self.failed_login_attempts = 0
            return False
        return True

    def reset_failed_logins(self) -> None:
        """Reset failed login counter after successful login."""
        self.failed_login_attempts = 0
        self.last_failed_login = None
        self.lockout_until = None


@dataclass
class User:
    """
    User account model.

    Represents a user in the system with roles and permissions.
    """
    id: str
    email: str
    username: str
    status: UserStatus = UserStatus.PENDING
    roles: Set[UserRole] = field(default_factory=set)
    custom_roles: Set[str] = field(default_factory=set)
    permissions: Set[str] = field(default_factory=set)
    tenant_id: Optional[str] = None
    workspace_ids: List[str] = field(default_factory=list)
    display_name: str = ""
    first_name: str = ""
    last_name: str = ""
    avatar_url: str = ""
    timezone: str = "UTC"
    locale: str = "en-US"
    credentials: Optional[UserCredentials] = None
    oauth_provider: Optional[str] = None
    oauth_subject: Optional[str] = None
    email_verified: bool = False
    phone: str = ""
    phone_verified: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    last_login_at: Optional[datetime] = None
    last_activity_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.display_name:
            self.display_name = self.username
        if isinstance(self.roles, list):
            self.roles = set(self.roles)
        if isinstance(self.custom_roles, list):
            self.custom_roles = set(self.custom_roles)
        if isinstance(self.permissions, list):
            self.permissions = set(self.permissions)

    def has_role(self, role: UserRole) -> bool:
        """Check if user has a specific role."""
        return role in self.roles

    def has_any_role(self, roles: List[UserRole]) -> bool:
        """Check if user has any of the specified roles."""
        return bool(self.roles.intersection(roles))

    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission."""
        return permission in self.permissions

    def is_admin(self) -> bool:
        """Check if user is an admin."""
        return UserRole.ADMIN in self.roles or UserRole.SUPER_ADMIN in self.roles

    def is_super_admin(self) -> bool:
        """Check if user is a super admin."""
        return UserRole.SUPER_ADMIN in self.roles

    def is_active(self) -> bool:
        """Check if user account is active."""
        return self.status == UserStatus.ACTIVE

    def add_role(self, role: UserRole) -> None:
        """Add a role to user."""
        self.roles.add(role)
        self.updated_at = datetime.utcnow()

    def remove_role(self, role: UserRole) -> None:
        """Remove a role from user."""
        self.roles.discard(role)
        self.updated_at = datetime.utcnow()

    def add_permission(self, permission: str) -> None:
        """Add a permission to user."""
        self.permissions.add(permission)
        self.updated_at = datetime.utcnow()

    def record_login(self) -> None:
        """Record a successful login."""
        self.last_login_at = datetime.utcnow()
        self.last_activity_at = datetime.utcnow()
        if self.credentials:
            self.credentials.reset_failed_logins()

    def record_activity(self) -> None:
        """Record user activity."""
        self.last_activity_at = datetime.utcnow()

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "status": self.status.value,
            "roles": [r.value for r in self.roles],
            "custom_roles": list(self.custom_roles),
            "permissions": list(self.permissions),
            "tenant_id": self.tenant_id,
            "workspace_ids": self.workspace_ids,
            "display_name": self.display_name,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "email_verified": self.email_verified,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
        }
        if include_sensitive:
            result["oauth_provider"] = self.oauth_provider
            result["mfa_enabled"] = self.credentials.mfa_enabled if self.credentials else False
        return result


@dataclass
class UserSession:
    """
    User session model.

    Represents an active user session.
    """
    id: str
    user_id: str
    token_hash: str
    ip_address: str = ""
    user_agent: str = ""
    device_info: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime = field(default_factory=lambda: datetime.utcnow() + timedelta(hours=24))
    last_activity_at: datetime = field(default_factory=datetime.utcnow)
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())

    def is_expired(self) -> bool:
        """Check if session is expired."""
        return datetime.utcnow() >= self.expires_at

    def is_valid(self) -> bool:
        """Check if session is valid (active and not expired)."""
        return self.is_active and not self.is_expired()

    def refresh(self, extend_hours: int = 24) -> None:
        """Refresh session expiration."""
        self.expires_at = datetime.utcnow() + timedelta(hours=extend_hours)
        self.last_activity_at = datetime.utcnow()

    def terminate(self) -> None:
        """Terminate the session."""
        self.is_active = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "last_activity_at": self.last_activity_at.isoformat(),
            "is_active": self.is_active,
        }


# =============================================================================
# API Key Models
# =============================================================================

@dataclass
class APIKeyScope:
    """
    API key scope/permissions.

    Defines what operations an API key can perform.
    """
    resources: List[str] = field(default_factory=lambda: ["*"])
    actions: List[str] = field(default_factory=lambda: ["read"])
    workspaces: List[str] = field(default_factory=lambda: ["*"])
    ip_whitelist: List[str] = field(default_factory=list)
    rate_limit_per_minute: int = 60
    rate_limit_per_day: int = 10000

    def allows_action(self, action: str) -> bool:
        """Check if scope allows an action."""
        return "*" in self.actions or action in self.actions

    def allows_resource(self, resource: str) -> bool:
        """Check if scope allows a resource."""
        if "*" in self.resources:
            return True
        for allowed in self.resources:
            if allowed.endswith("*") and resource.startswith(allowed[:-1]):
                return True
            if allowed == resource:
                return True
        return False

    def allows_workspace(self, workspace_id: str) -> bool:
        """Check if scope allows a workspace."""
        return "*" in self.workspaces or workspace_id in self.workspaces

    def allows_ip(self, ip_address: str) -> bool:
        """Check if IP is allowed (empty whitelist = allow all)."""
        if not self.ip_whitelist:
            return True
        return ip_address in self.ip_whitelist

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "resources": self.resources,
            "actions": self.actions,
            "workspaces": self.workspaces,
            "ip_whitelist": self.ip_whitelist,
            "rate_limit_per_minute": self.rate_limit_per_minute,
            "rate_limit_per_day": self.rate_limit_per_day,
        }


@dataclass
class APIKey:
    """
    API key model.

    Represents an API key for programmatic access.
    """
    id: str
    name: str
    key_prefix: str
    key_hash: str
    user_id: str
    tenant_id: Optional[str] = None
    status: APIKeyStatus = APIKeyStatus.ACTIVE
    scope: APIKeyScope = field(default_factory=APIKeyScope)
    description: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    use_count: int = 0
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[str] = None
    revoke_reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())

    @classmethod
    def generate(
        cls,
        name: str,
        user_id: str,
        tenant_id: Optional[str] = None,
        scope: Optional[APIKeyScope] = None,
        expires_in_days: Optional[int] = None,
    ) -> tuple["APIKey", str]:
        """
        Generate a new API key.

        Returns tuple of (APIKey, plaintext_key).
        The plaintext key is only available at creation time.
        """
        # Generate key: prefix_randomsecret
        prefix = "stk_" + secrets.token_hex(4)
        secret = secrets.token_hex(24)
        plaintext_key = f"{prefix}_{secret}"

        # Hash the full key for storage
        key_hash = hashlib.sha256(plaintext_key.encode()).hexdigest()

        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

        api_key = cls(
            id=str(uuid.uuid4()),
            name=name,
            key_prefix=prefix,
            key_hash=key_hash,
            user_id=user_id,
            tenant_id=tenant_id,
            scope=scope or APIKeyScope(),
            expires_at=expires_at,
        )

        return api_key, plaintext_key

    @staticmethod
    def hash_key(plaintext_key: str) -> str:
        """Hash a plaintext API key."""
        return hashlib.sha256(plaintext_key.encode()).hexdigest()

    def verify_key(self, plaintext_key: str) -> bool:
        """Verify a plaintext key against stored hash."""
        computed_hash = self.hash_key(plaintext_key)
        return secrets.compare_digest(computed_hash, self.key_hash)

    def is_valid(self) -> bool:
        """Check if API key is valid for use."""
        if self.status != APIKeyStatus.ACTIVE:
            return False
        if self.expires_at and datetime.utcnow() >= self.expires_at:
            return False
        return True

    def is_expired(self) -> bool:
        """Check if API key is expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() >= self.expires_at

    def record_use(self) -> None:
        """Record API key usage."""
        self.last_used_at = datetime.utcnow()
        self.use_count += 1

    def revoke(self, revoked_by: str, reason: str = "") -> None:
        """Revoke the API key."""
        self.status = APIKeyStatus.REVOKED
        self.revoked_at = datetime.utcnow()
        self.revoked_by = revoked_by
        self.revoke_reason = reason

    def to_dict(self, include_prefix: bool = True) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "id": self.id,
            "name": self.name,
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "status": self.status.value,
            "scope": self.scope.to_dict(),
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "use_count": self.use_count,
        }
        if include_prefix:
            result["key_prefix"] = self.key_prefix
        return result


# =============================================================================
# Token Models
# =============================================================================

@dataclass
class TokenPayload:
    """
    JWT token payload.

    Contains claims for the token.
    """
    sub: str  # Subject (user ID)
    type: TokenType = TokenType.ACCESS
    iss: str = "mantissa-stance"
    aud: str = "mantissa-stance-api"
    exp: Optional[datetime] = None
    iat: datetime = field(default_factory=datetime.utcnow)
    nbf: Optional[datetime] = None
    jti: str = field(default_factory=lambda: str(uuid.uuid4()))
    email: str = ""
    username: str = ""
    roles: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    tenant_id: Optional[str] = None
    workspace_id: Optional[str] = None
    session_id: Optional[str] = None
    impersonator_id: Optional[str] = None
    custom_claims: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JWT claims dictionary."""
        claims = {
            "sub": self.sub,
            "type": self.type.value,
            "iss": self.iss,
            "aud": self.aud,
            "iat": int(self.iat.timestamp()),
            "jti": self.jti,
        }
        if self.exp:
            claims["exp"] = int(self.exp.timestamp())
        if self.nbf:
            claims["nbf"] = int(self.nbf.timestamp())
        if self.email:
            claims["email"] = self.email
        if self.username:
            claims["username"] = self.username
        if self.roles:
            claims["roles"] = self.roles
        if self.permissions:
            claims["permissions"] = self.permissions
        if self.tenant_id:
            claims["tenant_id"] = self.tenant_id
        if self.workspace_id:
            claims["workspace_id"] = self.workspace_id
        if self.session_id:
            claims["session_id"] = self.session_id
        if self.impersonator_id:
            claims["impersonator_id"] = self.impersonator_id
        if self.custom_claims:
            claims.update(self.custom_claims)
        return claims

    @classmethod
    def from_dict(cls, claims: Dict[str, Any]) -> "TokenPayload":
        """Create from JWT claims dictionary."""
        return cls(
            sub=claims.get("sub", ""),
            type=TokenType(claims.get("type", "access")),
            iss=claims.get("iss", ""),
            aud=claims.get("aud", ""),
            exp=datetime.fromtimestamp(claims["exp"]) if "exp" in claims else None,
            iat=datetime.fromtimestamp(claims.get("iat", 0)),
            nbf=datetime.fromtimestamp(claims["nbf"]) if "nbf" in claims else None,
            jti=claims.get("jti", ""),
            email=claims.get("email", ""),
            username=claims.get("username", ""),
            roles=claims.get("roles", []),
            permissions=claims.get("permissions", []),
            tenant_id=claims.get("tenant_id"),
            workspace_id=claims.get("workspace_id"),
            session_id=claims.get("session_id"),
            impersonator_id=claims.get("impersonator_id"),
        )


@dataclass
class TokenPair:
    """
    Access and refresh token pair.

    Returned on successful authentication.
    """
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    refresh_expires_in: int = 86400
    scope: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to OAuth2-style response."""
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "refresh_expires_in": self.refresh_expires_in,
            "scope": self.scope,
        }


@dataclass
class RefreshToken:
    """
    Refresh token storage.

    Tracks refresh tokens for revocation.
    """
    id: str
    token_hash: str
    user_id: str
    session_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime = field(default_factory=lambda: datetime.utcnow() + timedelta(days=7))
    is_revoked: bool = False
    revoked_at: Optional[datetime] = None
    replaced_by: Optional[str] = None

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())

    def is_valid(self) -> bool:
        """Check if refresh token is valid."""
        if self.is_revoked:
            return False
        if datetime.utcnow() >= self.expires_at:
            return False
        return True

    def revoke(self, replaced_by: Optional[str] = None) -> None:
        """Revoke the refresh token."""
        self.is_revoked = True
        self.revoked_at = datetime.utcnow()
        self.replaced_by = replaced_by


# =============================================================================
# Audit Models
# =============================================================================

@dataclass
class AuditEvent:
    """
    Authentication audit event.

    Records authentication-related events for security monitoring.
    """
    id: str
    event_type: AuditEventType
    timestamp: datetime = field(default_factory=datetime.utcnow)
    user_id: Optional[str] = None
    username: Optional[str] = None
    tenant_id: Optional[str] = None
    ip_address: str = ""
    user_agent: str = ""
    resource: str = ""
    action: str = ""
    success: bool = True
    error_message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    request_id: str = ""
    session_id: Optional[str] = None

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/storage."""
        return {
            "id": self.id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "username": self.username,
            "tenant_id": self.tenant_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "resource": self.resource,
            "action": self.action,
            "success": self.success,
            "error_message": self.error_message,
            "details": self.details,
            "request_id": self.request_id,
            "session_id": self.session_id,
        }

    def to_log_line(self) -> str:
        """Convert to log line format."""
        status = "SUCCESS" if self.success else "FAILURE"
        return (
            f"[{self.timestamp.isoformat()}] {self.event_type.value} {status} "
            f"user={self.user_id or 'anonymous'} ip={self.ip_address} "
            f"resource={self.resource} action={self.action}"
        )
