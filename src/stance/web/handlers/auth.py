"""
Authentication handlers for the Stance web API.

This module handles all /api/auth/* endpoints for user management,
session management, API keys, roles, permissions, and audit logging.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


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

            if not email or not password:
                return HandlerResponse.error(
                    "Email and password required",
                    HttpStatus.BAD_REQUEST
                )

            # Demo: accept any login
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
