"""
Authentication handlers for the Stance web API.

This module handles all /api/auth/* endpoints for user management,
session management, API keys, roles, permissions, and audit logging.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


# =============================================================================
# Rate Limiter for Authentication Endpoints
# =============================================================================

@dataclass
class RateLimitEntry:
    """Tracks rate limit state for a single key."""
    attempts: int = 0
    first_attempt: datetime = field(default_factory=datetime.utcnow)
    locked_until: datetime | None = None


class AuthRateLimiter:
    """
    Thread-safe rate limiter for authentication endpoints.

    Implements progressive rate limiting with lockout periods:
    - 5 failed attempts in 5 minutes: 1 minute lockout
    - 10 failed attempts in 15 minutes: 5 minute lockout
    - 15 failed attempts in 30 minutes: 15 minute lockout
    - 20+ failed attempts: 1 hour lockout

    Uses both IP address and username/email for tracking to prevent
    both brute force attacks on single accounts and credential stuffing.
    """

    def __init__(self) -> None:
        self._entries: dict[str, RateLimitEntry] = defaultdict(RateLimitEntry)
        self._lock = threading.Lock()

        # Configuration
        self.window_seconds = 300  # 5 minutes
        self.max_attempts = 5
        self.lockout_thresholds = [
            (5, timedelta(minutes=1)),    # 5 attempts -> 1 min lockout
            (10, timedelta(minutes=5)),   # 10 attempts -> 5 min lockout
            (15, timedelta(minutes=15)),  # 15 attempts -> 15 min lockout
            (20, timedelta(hours=1)),     # 20+ attempts -> 1 hour lockout
        ]

    def _get_key(self, identifier: str, ip_address: str | None = None) -> str:
        """Generate a rate limit key from identifier and optional IP."""
        # Hash the identifier to prevent timing attacks and normalize length
        id_hash = hashlib.sha256(identifier.lower().encode()).hexdigest()[:16]
        if ip_address:
            ip_hash = hashlib.sha256(ip_address.encode()).hexdigest()[:8]
            return f"{id_hash}:{ip_hash}"
        return id_hash

    def _cleanup_old_entries(self) -> None:
        """Remove entries older than the longest window (1 hour)."""
        cutoff = datetime.utcnow() - timedelta(hours=1)
        keys_to_remove = [
            key for key, entry in self._entries.items()
            if entry.first_attempt < cutoff and entry.locked_until is None
        ]
        for key in keys_to_remove:
            del self._entries[key]

    def _get_lockout_duration(self, attempts: int) -> timedelta | None:
        """Get lockout duration based on attempt count."""
        for threshold, duration in reversed(self.lockout_thresholds):
            if attempts >= threshold:
                return duration
        return None

    def check_rate_limit(
        self,
        identifier: str,
        ip_address: str | None = None
    ) -> tuple[bool, str | None]:
        """
        Check if a login attempt is allowed.

        Args:
            identifier: Username or email being used for login
            ip_address: Client IP address (if available)

        Returns:
            Tuple of (allowed: bool, error_message: str | None)
        """
        with self._lock:
            self._cleanup_old_entries()

            now = datetime.utcnow()

            # Check both identifier-specific and IP-specific limits
            keys_to_check = [self._get_key(identifier)]
            if ip_address:
                keys_to_check.append(self._get_key("ip", ip_address))

            for key in keys_to_check:
                entry = self._entries[key]

                # Check if currently locked out
                if entry.locked_until and now < entry.locked_until:
                    remaining = (entry.locked_until - now).total_seconds()
                    return False, f"Too many login attempts. Try again in {int(remaining)} seconds."

                # Reset if outside window
                if (now - entry.first_attempt).total_seconds() > self.window_seconds:
                    entry.attempts = 0
                    entry.first_attempt = now
                    entry.locked_until = None

                # Check if over limit
                if entry.attempts >= self.max_attempts:
                    lockout = self._get_lockout_duration(entry.attempts)
                    if lockout:
                        entry.locked_until = now + lockout
                        remaining = lockout.total_seconds()
                        return False, f"Too many login attempts. Try again in {int(remaining)} seconds."

            return True, None

    def record_attempt(
        self,
        identifier: str,
        ip_address: str | None = None,
        success: bool = False
    ) -> None:
        """
        Record a login attempt.

        Args:
            identifier: Username or email used for login
            ip_address: Client IP address (if available)
            success: Whether the login was successful
        """
        with self._lock:
            now = datetime.utcnow()

            keys = [self._get_key(identifier)]
            if ip_address:
                keys.append(self._get_key("ip", ip_address))

            for key in keys:
                entry = self._entries[key]

                if success:
                    # Clear rate limit on successful login
                    entry.attempts = 0
                    entry.first_attempt = now
                    entry.locked_until = None
                else:
                    # Increment failed attempts
                    if (now - entry.first_attempt).total_seconds() > self.window_seconds:
                        entry.attempts = 1
                        entry.first_attempt = now
                    else:
                        entry.attempts += 1

                    # Check if we should lock
                    lockout = self._get_lockout_duration(entry.attempts)
                    if lockout and entry.attempts >= self.max_attempts:
                        entry.locked_until = now + lockout
                        logger.warning(
                            f"Rate limit lockout triggered for key {key[:8]}... "
                            f"({entry.attempts} attempts)"
                        )

    def check_and_record_attempt(
        self,
        identifier: str,
        ip_address: str | None = None,
    ) -> tuple[bool, str | None]:
        """
        Atomically check rate limit AND record the attempt.

        This prevents TOCTOU (time-of-check to time-of-use) race conditions
        where multiple concurrent requests could bypass rate limiting by
        checking before their attempts are recorded.

        Args:
            identifier: Username or email being used for login
            ip_address: Client IP address (if available)

        Returns:
            Tuple of (allowed: bool, error_message: str | None)
        """
        with self._lock:
            self._cleanup_old_entries()

            now = datetime.utcnow()

            # Check both identifier-specific and IP-specific limits
            keys = [self._get_key(identifier)]
            if ip_address:
                keys.append(self._get_key("ip", ip_address))

            # First, check if any key is locked
            for key in keys:
                entry = self._entries[key]

                # Check if currently locked out
                if entry.locked_until and now < entry.locked_until:
                    remaining = (entry.locked_until - now).total_seconds()
                    return False, f"Too many login attempts. Try again in {int(remaining)} seconds."

                # Reset if outside window
                if (now - entry.first_attempt).total_seconds() > self.window_seconds:
                    entry.attempts = 0
                    entry.first_attempt = now
                    entry.locked_until = None

                # Check if over limit (before recording new attempt)
                if entry.attempts >= self.max_attempts:
                    lockout = self._get_lockout_duration(entry.attempts)
                    if lockout:
                        entry.locked_until = now + lockout
                        remaining = lockout.total_seconds()
                        return False, f"Too many login attempts. Try again in {int(remaining)} seconds."

            # Atomically record the attempt for all keys
            for key in keys:
                entry = self._entries[key]
                if (now - entry.first_attempt).total_seconds() > self.window_seconds:
                    entry.attempts = 1
                    entry.first_attempt = now
                else:
                    entry.attempts += 1

            return True, None

    def record_success(
        self,
        identifier: str,
        ip_address: str | None = None,
    ) -> None:
        """
        Record a successful login, clearing rate limit state.

        Args:
            identifier: Username or email used for login
            ip_address: Client IP address (if available)
        """
        with self._lock:
            now = datetime.utcnow()

            keys = [self._get_key(identifier)]
            if ip_address:
                keys.append(self._get_key("ip", ip_address))

            for key in keys:
                entry = self._entries[key]
                entry.attempts = 0
                entry.first_attempt = now
                entry.locked_until = None

    def get_status(self, identifier: str, ip_address: str | None = None) -> dict[str, Any]:
        """Get rate limit status for an identifier."""
        with self._lock:
            key = self._get_key(identifier, ip_address)
            entry = self._entries.get(key, RateLimitEntry())

            now = datetime.utcnow()
            locked = entry.locked_until and now < entry.locked_until

            return {
                "attempts": entry.attempts,
                "max_attempts": self.max_attempts,
                "locked": locked,
                "locked_until": entry.locked_until.isoformat() if entry.locked_until else None,
                "window_seconds": self.window_seconds,
            }


# Global rate limiter instance for auth endpoints
_auth_rate_limiter = AuthRateLimiter()


class AuthHandler(RoutedHandler):
    """
    Handler for authentication API endpoints.

    Handles:
    - User management (list, show, create, delete, suspend, reactivate)
    - Session management (list, terminate, cleanup)
    - API key management (list, create, revoke, rotate)
    - Role management (list, show, assign, revoke)
    - Permission listing
    - Audit logging (list, security events, failed logins, stats)
    - Token operations (login, logout, refresh, validate)
    """

    base_path = "/api/auth/"

    # =========================================================================
    # Status and Summary GET endpoints
    # =========================================================================

    @route("status")
    def auth_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get authentication system status."""
        try:
            result = {
                "module": "auth",
                "version": "1.0.0",
                "status": "operational",
                "components": {
                    "UserManager": "available",
                    "JWTManager": "available",
                    "APIKeyManager": "available",
                    "SessionManager": "available",
                    "RBACManager": "available",
                    "AuditLogger": "available",
                    "OAuth2Provider": "available",
                    "AuthMiddleware": "available",
                },
                "capabilities": [
                    "user_management",
                    "jwt_authentication",
                    "api_key_authentication",
                    "session_management",
                    "role_based_access_control",
                    "oauth2_integration",
                    "oidc_integration",
                    "audit_logging",
                    "mfa_support",
                ],
                "statistics": {
                    "total_users": 0,
                    "active_sessions": 0,
                    "active_api_keys": 0,
                    "audit_events_24h": 0,
                },
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get auth status")
            return HandlerResponse.server_error(str(e))

    @route("summary")
    def auth_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get authentication summary."""
        try:
            result = {
                "users": {
                    "total": 5,
                    "active": 4,
                    "suspended": 1,
                    "pending_verification": 0,
                },
                "sessions": {
                    "total": 8,
                    "active": 6,
                },
                "api_keys": {
                    "total": 12,
                    "active": 10,
                    "expired": 2,
                },
                "audit": {
                    "events_24h": 45,
                    "failed_logins_24h": 3,
                    "security_events_24h": 8,
                },
                "roles": {
                    "system_roles": 6,
                    "custom_roles": 2,
                },
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get auth summary")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # User GET endpoints
    # =========================================================================

    @route("users")
    def users_list(self, params: dict, body: dict | None) -> HandlerResponse:
        """List users."""
        try:
            status_filter = self.get_param(params, "status", "")
            role_filter = self.get_param(params, "role", "")
            limit = self.get_param_int(params, "limit", 100)

            # Demo data
            users = [
                {
                    "id": "usr_001",
                    "email": "admin@example.com",
                    "username": "admin",
                    "display_name": "Admin User",
                    "status": "active",
                    "roles": ["admin", "analyst"],
                    "created_at": "2024-01-15T10:00:00Z",
                    "last_login_at": "2024-12-30T14:30:00Z",
                },
                {
                    "id": "usr_002",
                    "email": "analyst@example.com",
                    "username": "analyst",
                    "display_name": "Security Analyst",
                    "status": "active",
                    "roles": ["analyst"],
                    "created_at": "2024-02-01T09:00:00Z",
                    "last_login_at": "2024-12-29T16:45:00Z",
                },
            ]

            if status_filter:
                users = [u for u in users if u["status"] == status_filter]
            if role_filter:
                users = [u for u in users if role_filter in u["roles"]]

            return HandlerResponse.success({
                "users": users[:limit],
                "total": len(users),
                "limit": limit,
            })
        except Exception as e:
            logger.exception("Failed to list users")
            return HandlerResponse.server_error(str(e))

    @route("users/show")
    def users_show(self, params: dict, body: dict | None) -> HandlerResponse:
        """Show user details."""
        try:
            user_id = self.get_param(params, "user_id", "")

            result = {
                "id": user_id or "usr_001",
                "email": "admin@example.com",
                "username": "admin",
                "display_name": "Admin User",
                "status": "active",
                "roles": ["admin", "analyst"],
                "email_verified": True,
                "mfa_enabled": False,
                "created_at": "2024-01-15T10:00:00Z",
                "updated_at": "2024-12-01T08:00:00Z",
                "last_login_at": "2024-12-30T14:30:00Z",
                "last_login_ip": "192.168.1.100",
                "tenant_id": None,
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to show user")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # API Key GET endpoints
    # =========================================================================

    @route("apikeys")
    def apikeys_list(self, params: dict, body: dict | None) -> HandlerResponse:
        """List API keys."""
        try:
            user_id = self.get_param(params, "user_id", "")

            keys = [
                {
                    "id": "key_001",
                    "name": "Production API Key",
                    "prefix": "stance_prod_",
                    "user_id": "usr_001",
                    "status": "active",
                    "scopes": ["read:findings", "read:assets"],
                    "created_at": "2024-06-01T10:00:00Z",
                    "expires_at": "2025-06-01T10:00:00Z",
                    "last_used_at": "2024-12-30T12:00:00Z",
                    "use_count": 1523,
                },
                {
                    "id": "key_002",
                    "name": "CI/CD Integration",
                    "prefix": "stance_cicd_",
                    "user_id": "usr_001",
                    "status": "active",
                    "scopes": ["read:*", "scan:run"],
                    "created_at": "2024-08-15T14:00:00Z",
                    "expires_at": None,
                    "last_used_at": "2024-12-30T08:30:00Z",
                    "use_count": 856,
                },
            ]

            if user_id:
                keys = [k for k in keys if k["user_id"] == user_id]

            return HandlerResponse.success({
                "api_keys": keys,
                "total": len(keys),
            })
        except Exception as e:
            logger.exception("Failed to list API keys")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Session GET endpoints
    # =========================================================================

    @route("sessions")
    def sessions_list(self, params: dict, body: dict | None) -> HandlerResponse:
        """List active sessions."""
        try:
            user_id = self.get_param(params, "user_id", "")

            sessions = [
                {
                    "id": "sess_001",
                    "user_id": "usr_001",
                    "ip_address": "192.168.1.100",
                    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                    "created_at": "2024-12-30T14:30:00Z",
                    "expires_at": "2024-12-31T14:30:00Z",
                    "last_activity_at": "2024-12-30T15:45:00Z",
                },
                {
                    "id": "sess_002",
                    "user_id": "usr_002",
                    "ip_address": "10.0.0.50",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "created_at": "2024-12-29T16:45:00Z",
                    "expires_at": "2024-12-30T16:45:00Z",
                    "last_activity_at": "2024-12-30T10:00:00Z",
                },
            ]

            if user_id:
                sessions = [s for s in sessions if s["user_id"] == user_id]

            return HandlerResponse.success({
                "sessions": sessions,
                "total": len(sessions),
            })
        except Exception as e:
            logger.exception("Failed to list sessions")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Role GET endpoints
    # =========================================================================

    @route("roles")
    def roles_list(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available roles."""
        try:
            result = {
                "roles": [
                    {
                        "name": "super_admin",
                        "description": "Full system access with all permissions",
                        "permissions_count": 35,
                        "is_system": True,
                    },
                    {
                        "name": "admin",
                        "description": "Administrative access to most features",
                        "permissions_count": 30,
                        "is_system": True,
                    },
                    {
                        "name": "security_admin",
                        "description": "Security configuration and policy management",
                        "permissions_count": 20,
                        "is_system": True,
                    },
                    {
                        "name": "analyst",
                        "description": "View and analyze security findings",
                        "permissions_count": 15,
                        "is_system": True,
                    },
                    {
                        "name": "viewer",
                        "description": "Read-only access to findings and assets",
                        "permissions_count": 8,
                        "is_system": True,
                    },
                    {
                        "name": "api_user",
                        "description": "API-only access for integrations",
                        "permissions_count": 12,
                        "is_system": True,
                    },
                ],
                "total": 6,
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to list roles")
            return HandlerResponse.server_error(str(e))

    @route("roles/show")
    def roles_show(self, params: dict, body: dict | None) -> HandlerResponse:
        """Show role details."""
        try:
            role_name = self.get_param(params, "role_name", "admin")

            permissions = {
                "admin": [
                    "users:read", "users:write", "users:delete",
                    "findings:read", "findings:write", "findings:suppress",
                    "assets:read", "assets:write",
                    "policies:read", "policies:write",
                    "scans:read", "scans:run",
                    "reports:read", "reports:generate",
                    "config:read", "config:write",
                ],
                "analyst": [
                    "findings:read", "findings:write", "findings:suppress",
                    "assets:read",
                    "policies:read",
                    "scans:read",
                    "reports:read", "reports:generate",
                ],
                "viewer": [
                    "findings:read",
                    "assets:read",
                    "policies:read",
                    "scans:read",
                    "reports:read",
                ],
            }

            return HandlerResponse.success({
                "name": role_name,
                "description": f"Role: {role_name}",
                "permissions": permissions.get(role_name, []),
                "is_system": True,
            })
        except Exception as e:
            logger.exception("Failed to show role")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Permission GET endpoints
    # =========================================================================

    @route("permissions")
    def permissions_list(self, params: dict, body: dict | None) -> HandlerResponse:
        """List all permissions."""
        try:
            result = {
                "permissions": [
                    {"name": "users:read", "description": "View users", "resource": "users"},
                    {"name": "users:write", "description": "Create/update users", "resource": "users"},
                    {"name": "users:delete", "description": "Delete users", "resource": "users"},
                    {"name": "findings:read", "description": "View findings", "resource": "findings"},
                    {"name": "findings:write", "description": "Update findings", "resource": "findings"},
                    {"name": "findings:suppress", "description": "Suppress findings", "resource": "findings"},
                    {"name": "assets:read", "description": "View assets", "resource": "assets"},
                    {"name": "assets:write", "description": "Update assets", "resource": "assets"},
                    {"name": "policies:read", "description": "View policies", "resource": "policies"},
                    {"name": "policies:write", "description": "Create/update policies", "resource": "policies"},
                    {"name": "scans:read", "description": "View scan results", "resource": "scans"},
                    {"name": "scans:run", "description": "Run scans", "resource": "scans"},
                    {"name": "reports:read", "description": "View reports", "resource": "reports"},
                    {"name": "reports:generate", "description": "Generate reports", "resource": "reports"},
                    {"name": "config:read", "description": "View configuration", "resource": "config"},
                    {"name": "config:write", "description": "Update configuration", "resource": "config"},
                    {"name": "api_keys:read", "description": "View API keys", "resource": "api_keys"},
                    {"name": "api_keys:write", "description": "Create/revoke API keys", "resource": "api_keys"},
                ],
                "total": 18,
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to list permissions")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Audit GET endpoints
    # =========================================================================

    @route("audit")
    def audit_list(self, params: dict, body: dict | None) -> HandlerResponse:
        """List audit events."""
        try:
            user_id = self.get_param(params, "user_id", "")
            event_type = self.get_param(params, "event_type", "")
            limit = self.get_param_int(params, "limit", 100)

            events = [
                {
                    "id": "aud_001",
                    "event_type": "login_success",
                    "user_id": "usr_001",
                    "ip_address": "192.168.1.100",
                    "action": "login",
                    "status": "success",
                    "timestamp": "2024-12-30T14:30:00Z",
                },
                {
                    "id": "aud_002",
                    "event_type": "api_key_created",
                    "user_id": "usr_001",
                    "ip_address": "192.168.1.100",
                    "action": "create",
                    "status": "success",
                    "resource_type": "api_key",
                    "resource_id": "key_002",
                    "timestamp": "2024-12-30T14:35:00Z",
                },
                {
                    "id": "aud_003",
                    "event_type": "login_failure",
                    "user_id": "unknown",
                    "ip_address": "10.0.0.99",
                    "action": "login",
                    "status": "failure",
                    "error_message": "Invalid credentials",
                    "timestamp": "2024-12-30T13:00:00Z",
                },
            ]

            if user_id:
                events = [e for e in events if e["user_id"] == user_id]
            if event_type:
                events = [e for e in events if e["event_type"] == event_type]

            return HandlerResponse.success({
                "events": events[:limit],
                "total": len(events),
                "limit": limit,
            })
        except Exception as e:
            logger.exception("Failed to list audit events")
            return HandlerResponse.server_error(str(e))

    @route("audit/security")
    def audit_security(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get security-related audit events."""
        try:
            hours = self.get_param_int(params, "hours", 24)

            result = {
                "events": [
                    {
                        "id": "aud_003",
                        "event_type": "login_failure",
                        "user_id": None,
                        "ip_address": "10.0.0.99",
                        "status": "failure",
                        "error_message": "Invalid credentials",
                        "timestamp": "2024-12-30T13:00:00Z",
                    },
                    {
                        "id": "aud_004",
                        "event_type": "permission_denied",
                        "user_id": "usr_002",
                        "ip_address": "10.0.0.50",
                        "status": "failure",
                        "action": "users:delete",
                        "timestamp": "2024-12-30T10:15:00Z",
                    },
                ],
                "hours": hours,
                "total": 2,
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get security audit events")
            return HandlerResponse.server_error(str(e))

    @route("audit/failed-logins")
    def audit_failed_logins(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get failed login attempts."""
        try:
            hours = self.get_param_int(params, "hours", 24)

            result = {
                "events": [
                    {
                        "id": "aud_003",
                        "user_id": None,
                        "ip_address": "10.0.0.99",
                        "user_agent": "curl/7.79.1",
                        "error_message": "Invalid credentials",
                        "timestamp": "2024-12-30T13:00:00Z",
                    },
                ],
                "hours": hours,
                "total": 1,
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get failed logins")
            return HandlerResponse.server_error(str(e))

    @route("audit/stats")
    def audit_stats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get audit statistics."""
        try:
            result = {
                "total_events": 1523,
                "events_last_24h": 45,
                "failed_logins_24h": 3,
                "event_counts_24h": {
                    "login_success": 12,
                    "login_failure": 3,
                    "api_key_created": 2,
                    "permission_denied": 5,
                    "session_created": 12,
                    "session_terminated": 8,
                },
                "retention_days": 90,
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get audit stats")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Login/Logout POST endpoints
    # =========================================================================

    @route("login", methods=["POST"])
    def login(self, params: dict, body: dict | None) -> HandlerResponse:
        """Authenticate user and create session."""
        try:
            data = body or {}

            email = data.get("email", "")
            password = data.get("password", "")
            # Extract client IP from headers or params (typically set by reverse proxy)
            client_ip = data.get("_client_ip") or params.get("_client_ip")

            if not email or not password:
                return HandlerResponse.error(
                    "Email and password required",
                    HttpStatus.BAD_REQUEST
                )

            # Atomically check rate limit AND record the attempt
            # This prevents TOCTOU race conditions in concurrent requests
            allowed, error_msg = _auth_rate_limiter.check_and_record_attempt(email, client_ip)
            if not allowed:
                logger.warning(f"Login rate limited for email={email[:3]}*** ip={client_ip}")
                return HandlerResponse.error(
                    error_msg or "Too many login attempts",
                    HttpStatus.TOO_MANY_REQUESTS
                )

            # Demo: In production, this would validate against UserManager
            # For now, accept any login but record the attempt
            login_success = True  # Replace with actual validation

            # On success, clear rate limit state
            if login_success:
                _auth_rate_limiter.record_success(email, client_ip)

            if not login_success:
                # Use generic error to prevent user enumeration
                return HandlerResponse.error(
                    "Invalid credentials",
                    HttpStatus.UNAUTHORIZED
                )

            result = {
                "success": True,
                "user": {
                    "id": "usr_001",
                    "email": email,
                    "username": email.split("@")[0],
                    "roles": ["admin"],
                },
                "tokens": {
                    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                    "refresh_token": "refresh_token_placeholder",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                },
                "session_id": "sess_new_001",
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to login")
            return HandlerResponse.server_error(str(e))

    @route("logout", methods=["POST"])
    def logout(self, params: dict, body: dict | None) -> HandlerResponse:
        """Logout user and terminate session."""
        try:
            data = body or {}
            session_id = data.get("session_id", "")

            result = {
                "success": True,
                "message": f"Session {session_id or 'current'} terminated",
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to logout")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # User POST endpoints
    # =========================================================================

    @route("users/create", methods=["POST"])
    def users_create(self, params: dict, body: dict | None) -> HandlerResponse:
        """Create a new user."""
        try:
            data = body or {}

            email = data.get("email", "")
            username = data.get("username", "")
            password = data.get("password", "")

            if not email or not username or not password:
                return HandlerResponse.error(
                    "Email, username, and password required",
                    HttpStatus.BAD_REQUEST
                )

            result = {
                "success": True,
                "user": {
                    "id": "usr_new_001",
                    "email": email,
                    "username": username,
                    "status": "active",
                    "roles": data.get("roles", ["viewer"]),
                    "created_at": datetime.utcnow().isoformat() + "Z",
                },
            }
            return HandlerResponse.success(result, HttpStatus.CREATED)
        except Exception as e:
            logger.exception("Failed to create user")
            return HandlerResponse.server_error(str(e))

    @route("users/delete", methods=["POST"])
    def users_delete(self, params: dict, body: dict | None) -> HandlerResponse:
        """Delete a user."""
        try:
            data = body or {}
            user_id = data.get("user_id", "")

            if not user_id:
                return HandlerResponse.error("user_id required", HttpStatus.BAD_REQUEST)

            result = {
                "success": True,
                "message": f"User {user_id} deleted",
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to delete user")
            return HandlerResponse.server_error(str(e))

    @route("users/suspend", methods=["POST"])
    def users_suspend(self, params: dict, body: dict | None) -> HandlerResponse:
        """Suspend a user."""
        try:
            data = body or {}
            user_id = data.get("user_id", "")
            reason = data.get("reason", "")

            if not user_id:
                return HandlerResponse.error("user_id required", HttpStatus.BAD_REQUEST)

            result = {
                "success": True,
                "message": f"User {user_id} suspended",
                "reason": reason,
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to suspend user")
            return HandlerResponse.server_error(str(e))

    @route("users/reactivate", methods=["POST"])
    def users_reactivate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Reactivate a suspended user."""
        try:
            data = body or {}
            user_id = data.get("user_id", "")

            if not user_id:
                return HandlerResponse.error("user_id required", HttpStatus.BAD_REQUEST)

            result = {
                "success": True,
                "message": f"User {user_id} reactivated",
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to reactivate user")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # API Key POST endpoints
    # =========================================================================

    @route("apikeys/create", methods=["POST"])
    def apikeys_create(self, params: dict, body: dict | None) -> HandlerResponse:
        """Create a new API key."""
        try:
            data = body or {}
            name = data.get("name", "")

            if not name:
                return HandlerResponse.error("name required", HttpStatus.BAD_REQUEST)

            result = {
                "success": True,
                "api_key": {
                    "id": "key_new_001",
                    "name": name,
                    "prefix": "stance_",
                    "key": "stance_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                    "scopes": data.get("scopes", ["read:*"]),
                    "created_at": datetime.utcnow().isoformat() + "Z",
                    "expires_at": data.get("expires_at"),
                },
                "warning": "Save this key now. You will not be able to see it again.",
            }
            return HandlerResponse.success(result, HttpStatus.CREATED)
        except Exception as e:
            logger.exception("Failed to create API key")
            return HandlerResponse.server_error(str(e))

    @route("apikeys/revoke", methods=["POST"])
    def apikeys_revoke(self, params: dict, body: dict | None) -> HandlerResponse:
        """Revoke an API key."""
        try:
            data = body or {}
            key_id = data.get("key_id", "")

            if not key_id:
                return HandlerResponse.error("key_id required", HttpStatus.BAD_REQUEST)

            result = {
                "success": True,
                "message": f"API key {key_id} revoked",
                "reason": data.get("reason", ""),
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to revoke API key")
            return HandlerResponse.server_error(str(e))

    @route("apikeys/rotate", methods=["POST"])
    def apikeys_rotate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Rotate an API key."""
        try:
            data = body or {}
            key_id = data.get("key_id", "")

            if not key_id:
                return HandlerResponse.error("key_id required", HttpStatus.BAD_REQUEST)

            result = {
                "success": True,
                "old_key_id": key_id,
                "new_api_key": {
                    "id": "key_rotated_001",
                    "key": "stance_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
                    "created_at": datetime.utcnow().isoformat() + "Z",
                },
                "warning": "Save this key now. The old key has been revoked.",
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to rotate API key")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Session POST endpoints
    # =========================================================================

    @route("sessions/terminate", methods=["POST"])
    def sessions_terminate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Terminate a session."""
        try:
            data = body or {}
            session_id = data.get("session_id", "")
            user_id = data.get("user_id", "")

            if not session_id and not user_id:
                return HandlerResponse.error(
                    "session_id or user_id required",
                    HttpStatus.BAD_REQUEST
                )

            if user_id:
                result = {
                    "success": True,
                    "message": f"All sessions for user {user_id} terminated",
                    "terminated_count": 2,
                }
            else:
                result = {
                    "success": True,
                    "message": f"Session {session_id} terminated",
                }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to terminate session")
            return HandlerResponse.server_error(str(e))

    @route("sessions/cleanup", methods=["POST"])
    def sessions_cleanup(self, params: dict, body: dict | None) -> HandlerResponse:
        """Clean up expired sessions."""
        try:
            result = {
                "success": True,
                "message": "Expired sessions cleaned up",
                "removed_count": 5,
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to cleanup sessions")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Role POST endpoints
    # =========================================================================

    @route("roles/assign", methods=["POST"])
    def roles_assign(self, params: dict, body: dict | None) -> HandlerResponse:
        """Assign a role to a user."""
        try:
            data = body or {}
            user_id = data.get("user_id", "")
            role = data.get("role", "")

            if not user_id or not role:
                return HandlerResponse.error(
                    "user_id and role required",
                    HttpStatus.BAD_REQUEST
                )

            result = {
                "success": True,
                "message": f"Role '{role}' assigned to user {user_id}",
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to assign role")
            return HandlerResponse.server_error(str(e))

    @route("roles/revoke", methods=["POST"])
    def roles_revoke(self, params: dict, body: dict | None) -> HandlerResponse:
        """Revoke a role from a user."""
        try:
            data = body or {}
            user_id = data.get("user_id", "")
            role = data.get("role", "")

            if not user_id or not role:
                return HandlerResponse.error(
                    "user_id and role required",
                    HttpStatus.BAD_REQUEST
                )

            result = {
                "success": True,
                "message": f"Role '{role}' revoked from user {user_id}",
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to revoke role")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Token POST endpoints
    # =========================================================================

    @route("token/refresh", methods=["POST"])
    def token_refresh(self, params: dict, body: dict | None) -> HandlerResponse:
        """Refresh access token."""
        try:
            data = body or {}
            refresh_token = data.get("refresh_token", "")

            if not refresh_token:
                return HandlerResponse.error(
                    "refresh_token required",
                    HttpStatus.BAD_REQUEST
                )

            result = {
                "success": True,
                "tokens": {
                    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.new...",
                    "refresh_token": "new_refresh_token_placeholder",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                },
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to refresh token")
            return HandlerResponse.server_error(str(e))

    @route("token/validate", methods=["POST"])
    def token_validate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Validate an access token."""
        try:
            data = body or {}
            token = data.get("token", "")

            if not token:
                return HandlerResponse.error("token required", HttpStatus.BAD_REQUEST)

            result = {
                "valid": True,
                "payload": {
                    "user_id": "usr_001",
                    "email": "admin@example.com",
                    "roles": ["admin"],
                    "issued_at": "2024-12-30T14:30:00Z",
                    "expires_at": "2024-12-30T15:30:00Z",
                },
            }
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to validate token")
            return HandlerResponse.server_error(str(e))
