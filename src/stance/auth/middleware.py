"""
Authentication middleware for Mantissa Stance.

Provides request authentication and authorization middleware.

Part of Phase 92: API Gateway & Authentication
"""

from __future__ import annotations

import functools
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union

from stance.auth.models import (
    AuthMethod,
    User,
    UserRole,
    APIKey,
    TokenPayload,
    AuditEvent,
    AuditEventType,
)


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class AuthConfig:
    """
    Authentication middleware configuration.

    Attributes:
        enabled: Enable authentication
        allowed_methods: Allowed authentication methods
        public_paths: Paths that don't require authentication
        api_key_header: Header name for API key
        jwt_header: Header name for JWT token
        jwt_scheme: JWT authentication scheme (Bearer)
        require_https: Require HTTPS connections
        session_cookie_name: Session cookie name
        csrf_enabled: Enable CSRF protection
        rate_limit_enabled: Enable rate limiting
        audit_enabled: Enable audit logging
    """
    enabled: bool = True
    allowed_methods: List[AuthMethod] = field(
        default_factory=lambda: [AuthMethod.JWT, AuthMethod.API_KEY, AuthMethod.SESSION]
    )
    public_paths: List[str] = field(
        default_factory=lambda: ["/api/health", "/api/version", "/api/auth/login"]
    )
    api_key_header: str = "X-API-Key"
    jwt_header: str = "Authorization"
    jwt_scheme: str = "Bearer"
    require_https: bool = False
    session_cookie_name: str = "stance_session"
    csrf_enabled: bool = True
    rate_limit_enabled: bool = True
    audit_enabled: bool = True


# =============================================================================
# Auth Context
# =============================================================================

@dataclass
class AuthContext:
    """
    Authentication context for a request.

    Contains the authenticated user and request metadata.
    """
    user: Optional[User] = None
    api_key: Optional[APIKey] = None
    token_payload: Optional[TokenPayload] = None
    auth_method: AuthMethod = AuthMethod.NONE
    is_authenticated: bool = False
    tenant_id: Optional[str] = None
    workspace_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: str = ""
    user_agent: str = ""
    request_id: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def has_role(self, role: UserRole) -> bool:
        """Check if authenticated user has a role."""
        if self.user is None:
            return False
        return self.user.has_role(role)

    def has_permission(self, permission: str) -> bool:
        """Check if authenticated user has a permission."""
        if self.user is None:
            return False
        return self.user.has_permission(permission)

    def is_admin(self) -> bool:
        """Check if authenticated user is an admin."""
        if self.user is None:
            return False
        return self.user.is_admin()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "user_id": self.user.id if self.user else None,
            "username": self.user.username if self.user else None,
            "auth_method": self.auth_method.value,
            "is_authenticated": self.is_authenticated,
            "tenant_id": self.tenant_id,
            "workspace_id": self.workspace_id,
            "ip_address": self.ip_address,
            "request_id": self.request_id,
        }


@dataclass
class AuthResult:
    """Result of authentication attempt."""
    success: bool
    context: Optional[AuthContext] = None
    error: str = ""
    error_code: str = ""
    should_audit: bool = True

    @classmethod
    def authenticated(cls, context: AuthContext) -> "AuthResult":
        """Create successful authentication result."""
        return cls(success=True, context=context)

    @classmethod
    def failed(cls, error: str, error_code: str = "auth_failed") -> "AuthResult":
        """Create failed authentication result."""
        return cls(success=False, error=error, error_code=error_code)

    @classmethod
    def public_path(cls) -> "AuthResult":
        """Create result for public path (no auth required)."""
        return cls(
            success=True,
            context=AuthContext(is_authenticated=False),
            should_audit=False,
        )


# =============================================================================
# Auth Middleware
# =============================================================================

class AuthMiddleware:
    """
    Authentication middleware.

    Handles request authentication and authorization.
    """

    def __init__(
        self,
        config: Optional[AuthConfig] = None,
        jwt_manager=None,
        api_key_manager=None,
        session_manager=None,
        user_manager=None,
        rbac_manager=None,
        audit_logger=None,
    ):
        """
        Initialize authentication middleware.

        Args:
            config: Authentication configuration
            jwt_manager: JWT token manager
            api_key_manager: API key manager
            session_manager: Session manager
            user_manager: User manager
            rbac_manager: RBAC manager
            audit_logger: Audit logger
        """
        self.config = config or AuthConfig()
        self.jwt_manager = jwt_manager
        self.api_key_manager = api_key_manager
        self.session_manager = session_manager
        self.user_manager = user_manager
        self.rbac_manager = rbac_manager
        self.audit_logger = audit_logger

    def authenticate(
        self,
        path: str,
        headers: Dict[str, str],
        cookies: Optional[Dict[str, str]] = None,
        ip_address: str = "",
        user_agent: str = "",
        request_id: str = "",
    ) -> AuthResult:
        """
        Authenticate a request.

        Args:
            path: Request path
            headers: Request headers
            cookies: Request cookies
            ip_address: Client IP address
            user_agent: Client user agent
            request_id: Request correlation ID

        Returns:
            AuthResult with authentication outcome
        """
        # Check if authentication is disabled
        if not self.config.enabled:
            return AuthResult.public_path()

        # Check if path is public
        if self._is_public_path(path):
            return AuthResult.public_path()

        # Try each authentication method
        for method in self.config.allowed_methods:
            result = self._try_auth_method(
                method=method,
                headers=headers,
                cookies=cookies or {},
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )
            if result.success:
                return result

        # No authentication succeeded
        return AuthResult.failed(
            "Authentication required",
            error_code="authentication_required",
        )

    def _is_public_path(self, path: str) -> bool:
        """Check if path is public."""
        for public in self.config.public_paths:
            if public.endswith("*"):
                if path.startswith(public[:-1]):
                    return True
            elif path == public:
                return True
        return False

    def _try_auth_method(
        self,
        method: AuthMethod,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        ip_address: str,
        user_agent: str,
        request_id: str,
    ) -> AuthResult:
        """Try a specific authentication method."""
        if method == AuthMethod.JWT:
            return self._authenticate_jwt(headers, ip_address, user_agent, request_id)
        elif method == AuthMethod.API_KEY:
            return self._authenticate_api_key(headers, ip_address, user_agent, request_id)
        elif method == AuthMethod.SESSION:
            return self._authenticate_session(cookies, ip_address, user_agent, request_id)
        else:
            return AuthResult.failed(f"Unsupported auth method: {method.value}")

    def _authenticate_jwt(
        self,
        headers: Dict[str, str],
        ip_address: str,
        user_agent: str,
        request_id: str,
    ) -> AuthResult:
        """Authenticate using JWT token."""
        if self.jwt_manager is None:
            return AuthResult.failed("JWT authentication not configured")

        # Get authorization header
        auth_header = headers.get(self.config.jwt_header, "")
        if not auth_header:
            return AuthResult.failed("No authorization header")

        # Parse scheme and token
        parts = auth_header.split(" ", 1)
        if len(parts) != 2:
            return AuthResult.failed("Invalid authorization header format")

        scheme, token = parts
        if scheme.lower() != self.config.jwt_scheme.lower():
            return AuthResult.failed(f"Invalid auth scheme: {scheme}")

        try:
            # Validate token
            payload = self.jwt_manager.validate_token(token)

            # Get user
            user = None
            if self.user_manager:
                user = self.user_manager.get_user(payload.sub)

            context = AuthContext(
                user=user,
                token_payload=payload,
                auth_method=AuthMethod.JWT,
                is_authenticated=True,
                tenant_id=payload.tenant_id,
                workspace_id=payload.workspace_id,
                session_id=payload.session_id,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )

            return AuthResult.authenticated(context)

        except Exception as e:
            return AuthResult.failed(str(e), error_code="invalid_token")

    def _authenticate_api_key(
        self,
        headers: Dict[str, str],
        ip_address: str,
        user_agent: str,
        request_id: str,
    ) -> AuthResult:
        """Authenticate using API key."""
        if self.api_key_manager is None:
            return AuthResult.failed("API key authentication not configured")

        # Get API key from header
        api_key_value = headers.get(self.config.api_key_header, "")
        if not api_key_value:
            return AuthResult.failed("No API key provided")

        try:
            # Validate API key
            api_key = self.api_key_manager.validate_key(
                api_key_value,
                ip_address=ip_address,
            )

            # Record usage
            self.api_key_manager.use_key(api_key)

            # Get user
            user = None
            if self.user_manager:
                user = self.user_manager.get_user(api_key.user_id)

            context = AuthContext(
                user=user,
                api_key=api_key,
                auth_method=AuthMethod.API_KEY,
                is_authenticated=True,
                tenant_id=api_key.tenant_id,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )

            return AuthResult.authenticated(context)

        except Exception as e:
            return AuthResult.failed(str(e), error_code="invalid_api_key")

    def _authenticate_session(
        self,
        cookies: Dict[str, str],
        ip_address: str,
        user_agent: str,
        request_id: str,
    ) -> AuthResult:
        """Authenticate using session cookie."""
        if self.session_manager is None:
            return AuthResult.failed("Session authentication not configured")

        # Get session cookie
        session_token = cookies.get(self.config.session_cookie_name, "")
        if not session_token:
            return AuthResult.failed("No session cookie")

        try:
            # Validate session
            session = self.session_manager.validate_session(session_token)

            # Get user
            user = None
            if self.user_manager:
                user = self.user_manager.get_user(session.user_id)

            context = AuthContext(
                user=user,
                auth_method=AuthMethod.SESSION,
                is_authenticated=True,
                session_id=session.id,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
            )

            return AuthResult.authenticated(context)

        except Exception as e:
            return AuthResult.failed(str(e), error_code="invalid_session")

    def authorize(
        self,
        context: AuthContext,
        required_permission: Optional[str] = None,
        required_role: Optional[UserRole] = None,
        required_any_role: Optional[List[UserRole]] = None,
    ) -> bool:
        """
        Authorize an authenticated request.

        Args:
            context: Authentication context
            required_permission: Required permission
            required_role: Required specific role
            required_any_role: Any of these roles required

        Returns:
            True if authorized
        """
        if not context.is_authenticated:
            return False

        if context.user is None:
            return False

        # Check permission
        if required_permission:
            if self.rbac_manager:
                if not self.rbac_manager.check_permission(context.user, required_permission):
                    return False
            elif not context.user.has_permission(required_permission):
                return False

        # Check specific role
        if required_role:
            if not context.user.has_role(required_role):
                return False

        # Check any role
        if required_any_role:
            if not context.user.has_any_role(required_any_role):
                return False

        return True


# =============================================================================
# Decorators
# =============================================================================

F = TypeVar('F', bound=Callable[..., Any])


def require_auth(func: F) -> F:
    """
    Decorator to require authentication.

    The decorated function must accept an 'auth_context' parameter.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        context = kwargs.get('auth_context')
        if context is None or not context.is_authenticated:
            raise PermissionError("Authentication required")
        return func(*args, **kwargs)
    return wrapper  # type: ignore


def require_role(*roles: UserRole) -> Callable[[F], F]:
    """
    Decorator to require specific role(s).

    Args:
        roles: One or more required roles (user must have at least one)
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            context = kwargs.get('auth_context')
            if context is None or not context.is_authenticated:
                raise PermissionError("Authentication required")
            if context.user is None:
                raise PermissionError("User not found")
            if not context.user.has_any_role(list(roles)):
                raise PermissionError(f"Required role: {[r.value for r in roles]}")
            return func(*args, **kwargs)
        return wrapper  # type: ignore
    return decorator


def require_permission(*permissions: str) -> Callable[[F], F]:
    """
    Decorator to require specific permission(s).

    Args:
        permissions: One or more required permissions (user must have all)
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            context = kwargs.get('auth_context')
            if context is None or not context.is_authenticated:
                raise PermissionError("Authentication required")
            if context.user is None:
                raise PermissionError("User not found")
            for perm in permissions:
                if not context.user.has_permission(perm):
                    raise PermissionError(f"Required permission: {perm}")
            return func(*args, **kwargs)
        return wrapper  # type: ignore
    return decorator
