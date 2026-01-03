"""
API Gateway & Authentication Module for Mantissa Stance.

Provides comprehensive authentication and authorization capabilities:
- JWT token generation and validation
- API key management and authentication
- OAuth2/OIDC provider integration
- Role-based access control (RBAC)
- Session management
- Authentication middleware for web server
- Audit logging for authentication events

Components:
- User: User model with credentials and roles
- APIKey: API key model for programmatic access
- JWTManager: JWT token generation and validation
- OAuth2Provider: OAuth2/OIDC integration
- AuthMiddleware: Request authentication middleware
- RBACManager: Role-based access control
- SessionManager: Session lifecycle management
- AuditLogger: Authentication event logging

Part of Phase 92: API Gateway & Authentication
"""

from stance.auth.models import (
    # Enums
    AuthMethod,
    UserStatus,
    UserRole,
    APIKeyStatus,
    TokenType,
    AuditEventType,
    # User models
    UserCredentials,
    User,
    UserSession,
    # API Key models
    APIKey,
    APIKeyScope,
    # Token models
    TokenPayload,
    TokenPair,
    RefreshToken,
    # Audit models
    AuditEvent,
)

from stance.auth.jwt_manager import (
    JWTConfig,
    JWTManager,
    JWTError,
    TokenExpiredError,
    InvalidTokenError,
    create_jwt_manager,
)

from stance.auth.api_keys import (
    APIKeyConfig,
    APIKeyManager,
    APIKeyError,
    APIKeyNotFoundError,
    APIKeyExpiredError,
    APIKeyRevokedError,
    create_api_key_manager,
)

from stance.auth.oauth2 import (
    OAuth2Config,
    OAuth2Provider,
    OIDCConfig,
    OIDCProvider,
    OAuth2Error,
    OAuth2TokenError,
    create_oauth2_provider,
    create_oidc_provider,
)

from stance.auth.rbac import (
    Permission,
    Role,
    RBACConfig,
    RBACManager,
    RBACError,
    PermissionDeniedError,
    create_rbac_manager,
    get_default_roles,
)

from stance.auth.middleware import (
    AuthConfig,
    AuthContext,
    AuthMiddleware,
    AuthResult,
    require_auth,
    require_role,
    require_permission,
)

from stance.auth.session import (
    SessionConfig,
    Session,
    SessionManager,
    SessionError,
    SessionExpiredError,
    SessionNotFoundError,
    create_session_manager,
)

from stance.auth.audit import (
    AuditConfig,
    AuditLogger,
    create_audit_logger,
)

from stance.auth.user_manager import (
    UserConfig,
    UserManager,
    UserError,
    UserNotFoundError,
    UserExistsError,
    InvalidCredentialsError,
    create_user_manager,
)

__all__ = [
    # Enums
    "AuthMethod",
    "UserStatus",
    "UserRole",
    "APIKeyStatus",
    "TokenType",
    "AuditEventType",
    # User models
    "UserCredentials",
    "User",
    "UserSession",
    # API Key models
    "APIKey",
    "APIKeyScope",
    # Token models
    "TokenPayload",
    "TokenPair",
    "RefreshToken",
    # Audit models
    "AuditEvent",
    # JWT
    "JWTConfig",
    "JWTManager",
    "JWTError",
    "TokenExpiredError",
    "InvalidTokenError",
    "create_jwt_manager",
    # API Keys
    "APIKeyConfig",
    "APIKeyManager",
    "APIKeyError",
    "APIKeyNotFoundError",
    "APIKeyExpiredError",
    "APIKeyRevokedError",
    "create_api_key_manager",
    # OAuth2/OIDC
    "OAuth2Config",
    "OAuth2Provider",
    "OIDCConfig",
    "OIDCProvider",
    "OAuth2Error",
    "OAuth2TokenError",
    "create_oauth2_provider",
    "create_oidc_provider",
    # RBAC
    "Permission",
    "Role",
    "RBACConfig",
    "RBACManager",
    "RBACError",
    "PermissionDeniedError",
    "create_rbac_manager",
    "get_default_roles",
    # Middleware
    "AuthConfig",
    "AuthContext",
    "AuthMiddleware",
    "AuthResult",
    "require_auth",
    "require_role",
    "require_permission",
    # Session
    "SessionConfig",
    "Session",
    "SessionManager",
    "SessionError",
    "SessionExpiredError",
    "SessionNotFoundError",
    "create_session_manager",
    # Audit
    "AuditConfig",
    "AuditLogger",
    "create_audit_logger",
    # User Manager
    "UserConfig",
    "UserManager",
    "UserError",
    "UserNotFoundError",
    "UserExistsError",
    "InvalidCredentialsError",
    "create_user_manager",
]
