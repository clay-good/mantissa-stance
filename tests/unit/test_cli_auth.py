"""
Unit tests for authentication CLI commands.

Tests the CLI interface for authentication management:
- User management commands
- API key management commands
- Session management commands
- Role management commands
- Audit log viewing commands

Part of Phase 92: API Gateway & Authentication
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest


# =============================================================================
# User Management Tests
# =============================================================================

class TestUserManagement:
    """Tests for user management CLI commands."""

    def test_user_model_creation(self):
        """Test creating a user model."""
        from stance.auth.models import User, UserCredentials, UserRole, UserStatus

        credentials = UserCredentials()
        credentials.set_password("secure_password123!")

        user = User(
            id="usr_001",
            email="test@example.com",
            username="testuser",
            display_name="Test User",
            credentials=credentials,
            roles={UserRole.VIEWER},
            status=UserStatus.ACTIVE,
        )

        assert user.id == "usr_001"
        assert user.email == "test@example.com"
        assert user.username == "testuser"
        assert UserRole.VIEWER in user.roles
        assert user.status == UserStatus.ACTIVE

    def test_user_password_verification(self):
        """Test password verification."""
        from stance.auth.models import UserCredentials

        credentials = UserCredentials()
        credentials.set_password("my_secure_password!")

        assert credentials.verify_password("my_secure_password!")
        assert not credentials.verify_password("wrong_password")

    def test_user_lockout(self):
        """Test account lockout after failed attempts."""
        from stance.auth.models import UserCredentials

        credentials = UserCredentials(max_login_attempts=3, lockout_duration_minutes=30)
        credentials.set_password("password123!")

        # Record failed attempts
        for _ in range(3):
            credentials.record_failed_attempt()

        assert credentials.is_locked()

    def test_user_manager_registration(self):
        """Test user registration."""
        from stance.auth.user_manager import UserManager, UserConfig

        config = UserConfig(email_verification_required=False)
        manager = UserManager(config)

        user = manager.register_user(
            email="new@example.com",
            username="newuser",
            password="SecurePass123!",
            display_name="New User",
        )

        assert user.id is not None
        assert user.email == "new@example.com"
        assert user.username == "newuser"

    def test_user_manager_duplicate_email(self):
        """Test registration with duplicate email."""
        from stance.auth.user_manager import UserManager, UserConfig, UserExistsError

        config = UserConfig(email_verification_required=False)
        manager = UserManager(config)

        manager.register_user(
            email="test@example.com",
            username="user1",
            password="SecurePass123!",
        )

        with pytest.raises(UserExistsError):
            manager.register_user(
                email="test@example.com",
                username="user2",
                password="SecurePass123!",
            )

    def test_user_manager_authentication(self):
        """Test user authentication."""
        from stance.auth.user_manager import UserManager, UserConfig

        config = UserConfig(email_verification_required=False)
        manager = UserManager(config)

        manager.register_user(
            email="auth@example.com",
            username="authuser",
            password="AuthPass123!",
        )

        # Authenticate by email
        user = manager.authenticate("auth@example.com", "AuthPass123!")
        assert user.email == "auth@example.com"

        # Authenticate by username
        user = manager.authenticate("authuser", "AuthPass123!")
        assert user.username == "authuser"

    def test_user_manager_invalid_password(self):
        """Test authentication with invalid password."""
        from stance.auth.user_manager import UserManager, UserConfig, InvalidCredentialsError

        config = UserConfig(email_verification_required=False)
        manager = UserManager(config)

        manager.register_user(
            email="test@example.com",
            username="testuser",
            password="CorrectPass123!",
        )

        with pytest.raises(InvalidCredentialsError):
            manager.authenticate("test@example.com", "WrongPassword!")


# =============================================================================
# API Key Tests
# =============================================================================

class TestAPIKeyManagement:
    """Tests for API key management."""

    def test_api_key_creation(self):
        """Test creating an API key."""
        from stance.auth.api_keys import APIKeyManager

        manager = APIKeyManager()

        key, plaintext = manager.create_key(
            name="Test Key",
            user_id="usr_001",
            scopes=["read:findings", "read:assets"],
        )

        assert key.id is not None
        assert key.name == "Test Key"
        assert key.user_id == "usr_001"
        assert plaintext.startswith(key.prefix)

    def test_api_key_validation(self):
        """Test validating an API key."""
        from stance.auth.api_keys import APIKeyManager

        manager = APIKeyManager()

        key, plaintext = manager.create_key(
            name="Validate Key",
            user_id="usr_001",
        )

        validated = manager.validate_key(plaintext)
        assert validated.id == key.id
        assert validated.use_count == 1

    def test_api_key_expiration(self):
        """Test expired API key validation."""
        from stance.auth.api_keys import APIKeyManager, APIKeyExpiredError

        manager = APIKeyManager()

        key, plaintext = manager.create_key(
            name="Expired Key",
            user_id="usr_001",
            expires_in_days=-1,  # Already expired
        )

        with pytest.raises(APIKeyExpiredError):
            manager.validate_key(plaintext)

    def test_api_key_revocation(self):
        """Test revoking an API key."""
        from stance.auth.api_keys import APIKeyManager, APIKeyRevokedError

        manager = APIKeyManager()

        key, plaintext = manager.create_key(
            name="Revoke Key",
            user_id="usr_001",
        )

        manager.revoke_key(key.id, reason="Testing revocation")

        with pytest.raises(APIKeyRevokedError):
            manager.validate_key(plaintext)

    def test_api_key_rotation(self):
        """Test rotating an API key."""
        from stance.auth.api_keys import APIKeyManager

        manager = APIKeyManager()

        old_key, old_plaintext = manager.create_key(
            name="Rotate Key",
            user_id="usr_001",
        )

        new_key, new_plaintext = manager.rotate_key(old_key.id, user_id="usr_001")

        assert new_key.id != old_key.id
        assert new_key.name == old_key.name
        assert new_plaintext != old_plaintext


# =============================================================================
# JWT Tests
# =============================================================================

class TestJWTManagement:
    """Tests for JWT token management."""

    def test_jwt_token_generation(self):
        """Test generating JWT tokens."""
        from stance.auth.jwt_manager import JWTManager
        from stance.auth.models import User, UserCredentials, UserRole, UserStatus

        manager = JWTManager()

        user = User(
            id="usr_001",
            email="jwt@example.com",
            username="jwtuser",
            credentials=UserCredentials(),
            roles={UserRole.ADMIN},
            status=UserStatus.ACTIVE,
        )

        token_pair = manager.generate_tokens(user)

        assert token_pair.access_token is not None
        assert token_pair.refresh_token is not None
        assert token_pair.expires_in > 0

    def test_jwt_token_validation(self):
        """Test validating JWT tokens."""
        from stance.auth.jwt_manager import JWTManager
        from stance.auth.models import User, UserCredentials, UserRole, UserStatus

        manager = JWTManager()

        user = User(
            id="usr_001",
            email="validate@example.com",
            username="validateuser",
            credentials=UserCredentials(),
            roles={UserRole.ANALYST},
            status=UserStatus.ACTIVE,
        )

        token_pair = manager.generate_tokens(user)
        payload = manager.validate_token(token_pair.access_token)

        assert payload.user_id == "usr_001"
        assert payload.email == "validate@example.com"

    def test_jwt_token_refresh(self):
        """Test refreshing JWT tokens."""
        from stance.auth.jwt_manager import JWTManager
        from stance.auth.models import User, UserCredentials, UserRole, UserStatus

        manager = JWTManager()

        user = User(
            id="usr_001",
            email="refresh@example.com",
            username="refreshuser",
            credentials=UserCredentials(),
            roles={UserRole.VIEWER},
            status=UserStatus.ACTIVE,
        )

        original = manager.generate_tokens(user)
        refreshed = manager.refresh_tokens(original.refresh_token, user)

        assert refreshed.access_token != original.access_token

    def test_jwt_token_revocation(self):
        """Test revoking JWT tokens."""
        from stance.auth.jwt_manager import JWTManager, TokenExpiredError
        from stance.auth.models import User, UserCredentials, UserRole, UserStatus

        manager = JWTManager()

        user = User(
            id="usr_001",
            email="revoke@example.com",
            username="revokeuser",
            credentials=UserCredentials(),
            roles={UserRole.VIEWER},
            status=UserStatus.ACTIVE,
        )

        token_pair = manager.generate_tokens(user)
        manager.revoke_token(token_pair.access_token)

        with pytest.raises(TokenExpiredError):
            manager.validate_token(token_pair.access_token)


# =============================================================================
# Session Tests
# =============================================================================

class TestSessionManagement:
    """Tests for session management."""

    def test_session_creation(self):
        """Test creating a session."""
        from stance.auth.session import SessionManager

        manager = SessionManager()

        session, token = manager.create_session(
            user_id="usr_001",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
        )

        assert session.id is not None
        assert session.user_id == "usr_001"
        assert session.ip_address == "192.168.1.100"
        assert session.is_active

    def test_session_validation(self):
        """Test validating a session."""
        from stance.auth.session import SessionManager

        manager = SessionManager()

        session, token = manager.create_session(user_id="usr_001")
        validated = manager.validate_session(token)

        assert validated.id == session.id
        assert validated.user_id == "usr_001"

    def test_session_expiration(self):
        """Test session expiration check."""
        from stance.auth.session import Session
        from datetime import datetime, timedelta

        session = Session(
            id="sess_001",
            user_id="usr_001",
            token_hash="hash",
            expires_at=datetime.utcnow() - timedelta(hours=1),
        )

        assert session.is_expired()

    def test_session_idle_timeout(self):
        """Test session idle timeout."""
        from stance.auth.session import Session
        from datetime import datetime, timedelta

        session = Session(
            id="sess_001",
            user_id="usr_001",
            token_hash="hash",
            last_activity_at=datetime.utcnow() - timedelta(hours=10),
        )

        assert session.is_idle_timeout(idle_hours=8)

    def test_session_termination(self):
        """Test terminating a session."""
        from stance.auth.session import SessionManager, SessionNotFoundError

        manager = SessionManager()

        session, token = manager.create_session(user_id="usr_001")
        manager.terminate_session(session.id)

        with pytest.raises(Exception):  # SessionExpiredError or SessionNotFoundError
            manager.validate_session(token)

    def test_session_limit_enforcement(self):
        """Test max sessions per user enforcement."""
        from stance.auth.session import SessionManager, SessionConfig

        config = SessionConfig(max_sessions_per_user=2)
        manager = SessionManager(config)

        # Create 3 sessions for same user
        manager.create_session(user_id="usr_001")
        manager.create_session(user_id="usr_001")
        manager.create_session(user_id="usr_001")

        # Should have at most 2 sessions
        sessions = manager.get_user_sessions("usr_001")
        assert len(sessions) <= 2


# =============================================================================
# RBAC Tests
# =============================================================================

class TestRBAC:
    """Tests for role-based access control."""

    def test_permission_check(self):
        """Test checking permissions."""
        from stance.auth.rbac import RBACManager
        from stance.auth.models import User, UserCredentials, UserRole, UserStatus

        manager = RBACManager()

        user = User(
            id="usr_001",
            email="rbac@example.com",
            username="rbacuser",
            credentials=UserCredentials(),
            roles={UserRole.ANALYST},
            status=UserStatus.ACTIVE,
        )

        # Analyst should have read permissions
        assert manager.check_permission(user, "findings:read")
        assert manager.check_permission(user, "assets:read")

    def test_permission_denied(self):
        """Test permission denial."""
        from stance.auth.rbac import RBACManager, PermissionDeniedError
        from stance.auth.models import User, UserCredentials, UserRole, UserStatus

        manager = RBACManager()

        user = User(
            id="usr_001",
            email="viewer@example.com",
            username="vieweruser",
            credentials=UserCredentials(),
            roles={UserRole.VIEWER},
            status=UserStatus.ACTIVE,
        )

        # Viewer should not have write permissions
        with pytest.raises(PermissionDeniedError):
            manager.require_permission(user, "users:write")

    def test_role_hierarchy(self):
        """Test role permission inheritance."""
        from stance.auth.rbac import RBACManager
        from stance.auth.models import User, UserCredentials, UserRole, UserStatus

        manager = RBACManager()

        admin_user = User(
            id="usr_001",
            email="admin@example.com",
            username="adminuser",
            credentials=UserCredentials(),
            roles={UserRole.ADMIN},
            status=UserStatus.ACTIVE,
        )

        # Admin should have most permissions
        assert manager.check_permission(admin_user, "users:read")
        assert manager.check_permission(admin_user, "findings:read")
        assert manager.check_permission(admin_user, "policies:write")

    def test_get_user_permissions(self):
        """Test getting all permissions for a user."""
        from stance.auth.rbac import RBACManager
        from stance.auth.models import User, UserCredentials, UserRole, UserStatus

        manager = RBACManager()

        user = User(
            id="usr_001",
            email="multi@example.com",
            username="multiuser",
            credentials=UserCredentials(),
            roles={UserRole.ANALYST, UserRole.VIEWER},
            status=UserStatus.ACTIVE,
        )

        permissions = manager.get_user_permissions(user)
        assert "findings:read" in permissions
        assert "assets:read" in permissions


# =============================================================================
# Audit Tests
# =============================================================================

class TestAuditLogging:
    """Tests for audit logging."""

    def test_audit_event_creation(self):
        """Test creating an audit event."""
        from stance.auth.audit import AuditLogger
        from stance.auth.models import AuditEventType

        logger = AuditLogger()

        event = logger.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id="usr_001",
            ip_address="192.168.1.100",
            action="login",
            status="success",
        )

        assert event.id is not None
        assert event.event_type == AuditEventType.LOGIN_SUCCESS
        assert event.user_id == "usr_001"

    def test_audit_login_events(self):
        """Test logging login events."""
        from stance.auth.audit import AuditLogger

        logger = AuditLogger()

        # Log success
        success_event = logger.log_login_success(
            user_id="usr_001",
            ip_address="192.168.1.100",
        )
        assert success_event.status == "success"

        # Log failure
        failure_event = logger.log_login_failure(
            user_id="usr_001",
            ip_address="192.168.1.100",
            reason="Invalid password",
        )
        assert failure_event.status == "failure"

    def test_audit_query(self):
        """Test querying audit events."""
        from stance.auth.audit import AuditLogger
        from stance.auth.models import AuditEventType

        logger = AuditLogger()

        # Create some events
        logger.log_login_success(user_id="usr_001", ip_address="10.0.0.1")
        logger.log_login_failure(user_id="usr_002", ip_address="10.0.0.2")
        logger.log_login_success(user_id="usr_001", ip_address="10.0.0.3")

        # Query by user
        events = logger.get_events(user_id="usr_001")
        assert len(events) == 2

        # Query by type
        failures = logger.get_events(event_type=AuditEventType.LOGIN_FAILURE)
        assert len(failures) == 1

    def test_audit_sensitive_field_redaction(self):
        """Test sensitive field redaction."""
        from stance.auth.audit import AuditLogger
        from stance.auth.models import AuditEventType

        logger = AuditLogger()

        event = logger.log_event(
            event_type=AuditEventType.PASSWORD_CHANGED,
            user_id="usr_001",
            ip_address="192.168.1.100",
            metadata={
                "password": "secret123",
                "new_password": "newsecret456",
                "reason": "User requested",
            },
        )

        assert event.metadata.get("password") == "[REDACTED]"
        assert event.metadata.get("new_password") == "[REDACTED]"
        assert event.metadata.get("reason") == "User requested"


# =============================================================================
# OAuth2 Tests
# =============================================================================

class TestOAuth2:
    """Tests for OAuth2 integration."""

    def test_oauth2_authorization_url(self):
        """Test generating OAuth2 authorization URL."""
        from stance.auth.oauth2 import OAuth2Provider, OAuth2Config

        config = OAuth2Config(
            client_id="test_client",
            client_secret="test_secret",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
        )
        provider = OAuth2Provider(config)

        url, state = provider.generate_authorization_url(
            redirect_uri="https://app.example.com/callback",
            scopes=["openid", "profile"],
        )

        assert "https://auth.example.com/authorize" in url
        assert "client_id=test_client" in url
        assert state.state is not None

    def test_oidc_provider_creation(self):
        """Test creating OIDC provider."""
        from stance.auth.oauth2 import OIDCProvider, OIDCConfig

        config = OIDCConfig(
            client_id="oidc_client",
            client_secret="oidc_secret",
            issuer="https://issuer.example.com",
            authorization_endpoint="https://issuer.example.com/authorize",
            token_endpoint="https://issuer.example.com/token",
            userinfo_endpoint="https://issuer.example.com/userinfo",
            jwks_uri="https://issuer.example.com/.well-known/jwks.json",
        )
        provider = OIDCProvider(config)

        assert provider.config.issuer == "https://issuer.example.com"


# =============================================================================
# Middleware Tests
# =============================================================================

class TestAuthMiddleware:
    """Tests for authentication middleware."""

    def test_middleware_jwt_auth(self):
        """Test JWT authentication via middleware."""
        from stance.auth.middleware import AuthMiddleware, AuthConfig
        from stance.auth.jwt_manager import JWTManager
        from stance.auth.models import User, UserCredentials, UserRole, UserStatus, AuthMethod

        jwt_manager = JWTManager()
        config = AuthConfig(jwt_manager=jwt_manager)
        middleware = AuthMiddleware(config)

        # Create a user and token
        user = User(
            id="usr_001",
            email="middleware@example.com",
            username="middlewareuser",
            credentials=UserCredentials(),
            roles={UserRole.ADMIN},
            status=UserStatus.ACTIVE,
        )
        token_pair = jwt_manager.generate_tokens(user)

        # Authenticate with token
        result = middleware.authenticate(
            path="/api/findings",
            headers={"Authorization": f"Bearer {token_pair.access_token}"},
        )

        assert result.authenticated
        assert result.auth_method == AuthMethod.JWT
        assert result.context.user_id == "usr_001"

    def test_middleware_public_path(self):
        """Test public path bypass."""
        from stance.auth.middleware import AuthMiddleware, AuthConfig

        config = AuthConfig(public_paths=["/api/health", "/api/version"])
        middleware = AuthMiddleware(config)

        result = middleware.authenticate(
            path="/api/health",
            headers={},
        )

        assert result.authenticated
        assert result.context is None


# =============================================================================
# Factory Function Tests
# =============================================================================

class TestFactoryFunctions:
    """Tests for factory functions."""

    def test_create_user_manager(self):
        """Test user manager factory."""
        from stance.auth import create_user_manager

        manager = create_user_manager(
            password_min_length=10,
            max_login_attempts=3,
            email_verification_required=False,
        )

        assert manager.config.password_min_length == 10
        assert manager.config.max_login_attempts == 3

    def test_create_api_key_manager(self):
        """Test API key manager factory."""
        from stance.auth import create_api_key_manager

        manager = create_api_key_manager(
            key_prefix="test_",
            default_expiry_days=30,
        )

        assert manager.config.key_prefix == "test_"
        assert manager.config.default_expiry_days == 30

    def test_create_session_manager(self):
        """Test session manager factory."""
        from stance.auth import create_session_manager

        manager = create_session_manager(
            lifetime_hours=12,
            idle_timeout_hours=4,
            max_per_user=3,
        )

        assert manager.config.session_lifetime_hours == 12
        assert manager.config.session_idle_timeout_hours == 4
        assert manager.config.max_sessions_per_user == 3

    def test_create_rbac_manager(self):
        """Test RBAC manager factory."""
        from stance.auth import create_rbac_manager

        manager = create_rbac_manager()

        # Should have default roles
        roles = list(manager._roles.values())
        assert len(roles) > 0

    def test_create_jwt_manager(self):
        """Test JWT manager factory."""
        from stance.auth import create_jwt_manager

        manager = create_jwt_manager(
            access_token_expiry_minutes=30,
            refresh_token_expiry_days=7,
        )

        assert manager.config.access_token_expiry_minutes == 30
        assert manager.config.refresh_token_expiry_days == 7

    def test_create_audit_logger(self):
        """Test audit logger factory."""
        from stance.auth import create_audit_logger

        logger = create_audit_logger(
            log_to_console=True,
            retention_days=60,
        )

        assert logger.config.log_to_console is True
        assert logger.config.retention_days == 60


# =============================================================================
# Integration Tests
# =============================================================================

class TestAuthIntegration:
    """Integration tests for authentication system."""

    def test_full_authentication_flow(self):
        """Test complete authentication flow."""
        from stance.auth import (
            create_user_manager,
            create_jwt_manager,
            create_session_manager,
            create_audit_logger,
        )
        from stance.auth.models import UserRole

        # Initialize managers
        user_manager = create_user_manager(email_verification_required=False)
        jwt_manager = create_jwt_manager()
        session_manager = create_session_manager()
        audit_logger = create_audit_logger(log_to_console=False)

        # Register user
        user = user_manager.register_user(
            email="integration@example.com",
            username="integrationuser",
            password="IntegrationPass123!",
            roles={UserRole.ANALYST},
        )

        # Authenticate
        authenticated_user = user_manager.authenticate(
            "integration@example.com",
            "IntegrationPass123!",
            ip_address="192.168.1.100",
        )
        assert authenticated_user.id == user.id

        # Generate tokens
        tokens = jwt_manager.generate_tokens(authenticated_user)
        assert tokens.access_token is not None

        # Create session
        session, session_token = session_manager.create_session(
            user_id=authenticated_user.id,
            ip_address="192.168.1.100",
            user_agent="Test Agent",
        )
        assert session.user_id == authenticated_user.id

        # Log audit event
        audit_logger.log_login_success(
            user_id=authenticated_user.id,
            ip_address="192.168.1.100",
        )

        # Validate token
        payload = jwt_manager.validate_token(tokens.access_token)
        assert payload.user_id == authenticated_user.id

        # Validate session
        validated_session = session_manager.validate_session(session_token)
        assert validated_session.id == session.id

        # Logout
        session_manager.terminate_session(session.id)
        jwt_manager.revoke_token(tokens.access_token)

        audit_logger.log_logout(
            user_id=authenticated_user.id,
            ip_address="192.168.1.100",
        )


# =============================================================================
# Run Tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
