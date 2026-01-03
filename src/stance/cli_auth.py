"""
Authentication CLI commands for Mantissa Stance.

Provides CLI interface for authentication management:
- User management (create, list, update, delete)
- API key management (create, list, revoke, rotate)
- Session management (list, terminate)
- Role management (assign, revoke)
- Audit log viewing

Part of Phase 92: API Gateway & Authentication
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

from stance.auth import (
    # Managers
    UserManager,
    UserConfig,
    APIKeyManager,
    APIKeyConfig,
    SessionManager,
    SessionConfig,
    RBACManager,
    RBACConfig,
    JWTManager,
    JWTConfig,
    AuditLogger,
    AuditConfig,
    # Models
    UserRole,
    UserStatus,
    APIKeyStatus,
    AuditEventType,
    # Factory functions
    create_user_manager,
    create_api_key_manager,
    create_session_manager,
    create_rbac_manager,
    create_jwt_manager,
    create_audit_logger,
    get_default_roles,
    # Exceptions
    UserError,
    UserNotFoundError,
    UserExistsError,
    InvalidCredentialsError,
    APIKeyError,
    SessionError,
    RBACError,
)


# =============================================================================
# Helper Functions
# =============================================================================

def _format_datetime(dt: Optional[datetime]) -> str:
    """Format datetime for display."""
    if dt is None:
        return "-"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _format_table(headers: List[str], rows: List[List[str]]) -> str:
    """Format data as a table."""
    if not rows:
        return "No data to display."

    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))

    # Build table
    lines = []

    # Header
    header_line = " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    lines.append(header_line)
    lines.append("-" * len(header_line))

    # Rows
    for row in rows:
        row_line = " | ".join(
            str(cell).ljust(widths[i]) for i, cell in enumerate(row)
        )
        lines.append(row_line)

    return "\n".join(lines)


def _output_result(data: Any, format_type: str = "table") -> None:
    """Output result in specified format."""
    if format_type == "json":
        print(json.dumps(data, indent=2, default=str))
    else:
        print(data)


# =============================================================================
# Global Manager Instances (in-memory for demo)
# =============================================================================

_user_manager: Optional[UserManager] = None
_api_key_manager: Optional[APIKeyManager] = None
_session_manager: Optional[SessionManager] = None
_rbac_manager: Optional[RBACManager] = None
_jwt_manager: Optional[JWTManager] = None
_audit_logger: Optional[AuditLogger] = None


def _get_user_manager() -> UserManager:
    global _user_manager
    if _user_manager is None:
        _user_manager = create_user_manager(email_verification_required=False)
    return _user_manager


def _get_api_key_manager() -> APIKeyManager:
    global _api_key_manager
    if _api_key_manager is None:
        _api_key_manager = create_api_key_manager()
    return _api_key_manager


def _get_session_manager() -> SessionManager:
    global _session_manager
    if _session_manager is None:
        _session_manager = create_session_manager()
    return _session_manager


def _get_rbac_manager() -> RBACManager:
    global _rbac_manager
    if _rbac_manager is None:
        _rbac_manager = create_rbac_manager()
    return _rbac_manager


def _get_jwt_manager() -> JWTManager:
    global _jwt_manager
    if _jwt_manager is None:
        _jwt_manager = create_jwt_manager()
    return _jwt_manager


def _get_audit_logger() -> AuditLogger:
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = create_audit_logger(log_to_console=True)
    return _audit_logger


# =============================================================================
# User Commands
# =============================================================================

def cmd_auth_users_list(args: argparse.Namespace) -> int:
    """List users."""
    manager = _get_user_manager()

    status = None
    if hasattr(args, "status") and args.status:
        status = UserStatus(args.status)

    role = None
    if hasattr(args, "role") and args.role:
        role = UserRole(args.role)

    users = manager.list_users(
        status=status,
        role=role,
        limit=getattr(args, "limit", 100),
    )

    if args.format == "json":
        data = [
            {
                "id": u.id,
                "email": u.email,
                "username": u.username,
                "display_name": u.display_name,
                "status": u.status.value,
                "roles": [r.value for r in u.roles],
                "created_at": u.created_at.isoformat(),
                "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
            }
            for u in users
        ]
        _output_result(data, "json")
    else:
        headers = ["ID", "Email", "Username", "Status", "Roles", "Created"]
        rows = [
            [
                u.id[:12] + "...",
                u.email,
                u.username,
                u.status.value,
                ",".join(r.value for r in u.roles),
                _format_datetime(u.created_at),
            ]
            for u in users
        ]
        print(_format_table(headers, rows))
        print(f"\nTotal: {len(users)} users")

    return 0


def cmd_auth_users_create(args: argparse.Namespace) -> int:
    """Create a new user."""
    manager = _get_user_manager()
    audit = _get_audit_logger()

    try:
        roles = set()
        if hasattr(args, "roles") and args.roles:
            for role_str in args.roles.split(","):
                try:
                    roles.add(UserRole(role_str.strip()))
                except ValueError:
                    print(f"Error: Invalid role '{role_str}'")
                    return 1

        user = manager.register_user(
            email=args.email,
            username=args.username,
            password=args.password,
            display_name=getattr(args, "display_name", "") or args.username,
            roles=roles or {UserRole.VIEWER},
        )

        audit.log_user_created(
            created_user_id=user.id,
            created_by_user_id="cli",
            metadata={"email": user.email, "username": user.username},
        )

        if args.format == "json":
            _output_result({
                "id": user.id,
                "email": user.email,
                "username": user.username,
                "status": user.status.value,
                "roles": [r.value for r in user.roles],
            }, "json")
        else:
            print(f"User created successfully:")
            print(f"  ID: {user.id}")
            print(f"  Email: {user.email}")
            print(f"  Username: {user.username}")
            print(f"  Status: {user.status.value}")
            print(f"  Roles: {', '.join(r.value for r in user.roles)}")

        return 0

    except UserExistsError as e:
        print(f"Error: {e}")
        return 1
    except Exception as e:
        print(f"Error creating user: {e}")
        return 1


def cmd_auth_users_show(args: argparse.Namespace) -> int:
    """Show user details."""
    manager = _get_user_manager()

    user = manager.get_user(args.user_id)
    if user is None:
        # Try by email
        user = manager.get_user_by_email(args.user_id)
    if user is None:
        # Try by username
        user = manager.get_user_by_username(args.user_id)

    if user is None:
        print(f"Error: User not found: {args.user_id}")
        return 1

    if args.format == "json":
        _output_result({
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "display_name": user.display_name,
            "status": user.status.value,
            "roles": [r.value for r in user.roles],
            "email_verified": user.email_verified,
            "mfa_enabled": user.credentials.mfa_enabled,
            "created_at": user.created_at.isoformat(),
            "updated_at": user.updated_at.isoformat() if user.updated_at else None,
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
            "last_login_ip": user.last_login_ip,
        }, "json")
    else:
        print(f"User Details:")
        print(f"  ID: {user.id}")
        print(f"  Email: {user.email}")
        print(f"  Username: {user.username}")
        print(f"  Display Name: {user.display_name}")
        print(f"  Status: {user.status.value}")
        print(f"  Roles: {', '.join(r.value for r in user.roles)}")
        print(f"  Email Verified: {user.email_verified}")
        print(f"  MFA Enabled: {user.credentials.mfa_enabled}")
        print(f"  Created: {_format_datetime(user.created_at)}")
        print(f"  Last Login: {_format_datetime(user.last_login_at)}")
        print(f"  Last Login IP: {user.last_login_ip or '-'}")

    return 0


def cmd_auth_users_delete(args: argparse.Namespace) -> int:
    """Delete a user."""
    manager = _get_user_manager()
    audit = _get_audit_logger()

    if not getattr(args, "force", False):
        confirm = input(f"Delete user {args.user_id}? [y/N]: ")
        if confirm.lower() != "y":
            print("Cancelled.")
            return 0

    if manager.delete_user(args.user_id):
        audit.log_user_deleted(
            deleted_user_id=args.user_id,
            deleted_by_user_id="cli",
        )
        print(f"User {args.user_id} deleted.")
        return 0
    else:
        print(f"Error: User not found: {args.user_id}")
        return 1


def cmd_auth_users_suspend(args: argparse.Namespace) -> int:
    """Suspend a user."""
    manager = _get_user_manager()

    try:
        reason = getattr(args, "reason", "")
        user = manager.suspend_user(args.user_id, reason=reason)
        print(f"User {user.username} suspended.")
        return 0
    except UserNotFoundError:
        print(f"Error: User not found: {args.user_id}")
        return 1


def cmd_auth_users_reactivate(args: argparse.Namespace) -> int:
    """Reactivate a suspended user."""
    manager = _get_user_manager()

    try:
        user = manager.reactivate_user(args.user_id)
        print(f"User {user.username} reactivated.")
        return 0
    except UserNotFoundError:
        print(f"Error: User not found: {args.user_id}")
        return 1


# =============================================================================
# API Key Commands
# =============================================================================

def cmd_auth_apikeys_list(args: argparse.Namespace) -> int:
    """List API keys."""
    manager = _get_api_key_manager()

    user_id = getattr(args, "user_id", None)
    keys = manager.list_keys(user_id=user_id)

    if args.format == "json":
        data = [
            {
                "id": k.id,
                "name": k.name,
                "user_id": k.user_id,
                "status": k.status.value,
                "created_at": k.created_at.isoformat(),
                "expires_at": k.expires_at.isoformat() if k.expires_at else None,
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
                "use_count": k.use_count,
            }
            for k in keys
        ]
        _output_result(data, "json")
    else:
        headers = ["ID", "Name", "User", "Status", "Created", "Expires", "Uses"]
        rows = [
            [
                k.id[:12] + "...",
                k.name[:20],
                k.user_id[:12] + "..." if k.user_id else "-",
                k.status.value,
                _format_datetime(k.created_at),
                _format_datetime(k.expires_at) if k.expires_at else "Never",
                str(k.use_count),
            ]
            for k in keys
        ]
        print(_format_table(headers, rows))
        print(f"\nTotal: {len(keys)} API keys")

    return 0


def cmd_auth_apikeys_create(args: argparse.Namespace) -> int:
    """Create a new API key."""
    manager = _get_api_key_manager()
    audit = _get_audit_logger()

    try:
        scopes = None
        if hasattr(args, "scopes") and args.scopes:
            scopes = [s.strip() for s in args.scopes.split(",")]

        expires_days = getattr(args, "expires_days", None)

        key, plaintext = manager.create_key(
            name=args.name,
            user_id=getattr(args, "user_id", "cli-generated"),
            scopes=scopes,
            expires_in_days=expires_days,
        )

        audit.log_api_key_created(
            user_id=key.user_id,
            key_id=key.id,
            key_name=key.name,
        )

        if args.format == "json":
            _output_result({
                "id": key.id,
                "name": key.name,
                "key": plaintext,
                "prefix": key.prefix,
                "expires_at": key.expires_at.isoformat() if key.expires_at else None,
            }, "json")
        else:
            print(f"API Key created successfully:")
            print(f"  ID: {key.id}")
            print(f"  Name: {key.name}")
            print(f"  Prefix: {key.prefix}")
            print(f"  Expires: {_format_datetime(key.expires_at) if key.expires_at else 'Never'}")
            print()
            print(f"  API Key: {plaintext}")
            print()
            print("  IMPORTANT: Save this key now. You will not be able to see it again.")

        return 0

    except APIKeyError as e:
        print(f"Error: {e}")
        return 1


def cmd_auth_apikeys_revoke(args: argparse.Namespace) -> int:
    """Revoke an API key."""
    manager = _get_api_key_manager()
    audit = _get_audit_logger()

    if manager.revoke_key(args.key_id, reason=getattr(args, "reason", "")):
        audit.log_api_key_revoked(
            user_id="cli",
            key_id=args.key_id,
            reason=getattr(args, "reason", ""),
        )
        print(f"API key {args.key_id} revoked.")
        return 0
    else:
        print(f"Error: API key not found: {args.key_id}")
        return 1


def cmd_auth_apikeys_rotate(args: argparse.Namespace) -> int:
    """Rotate an API key."""
    manager = _get_api_key_manager()

    try:
        expires_days = getattr(args, "expires_days", None)
        new_key, plaintext = manager.rotate_key(
            args.key_id,
            user_id="cli",
            expires_in_days=expires_days,
        )

        if args.format == "json":
            _output_result({
                "id": new_key.id,
                "name": new_key.name,
                "key": plaintext,
                "prefix": new_key.prefix,
                "expires_at": new_key.expires_at.isoformat() if new_key.expires_at else None,
            }, "json")
        else:
            print(f"API Key rotated successfully:")
            print(f"  New ID: {new_key.id}")
            print(f"  Name: {new_key.name}")
            print(f"  Prefix: {new_key.prefix}")
            print()
            print(f"  New API Key: {plaintext}")
            print()
            print("  IMPORTANT: Save this key now. The old key has been revoked.")

        return 0

    except APIKeyError as e:
        print(f"Error: {e}")
        return 1


# =============================================================================
# Session Commands
# =============================================================================

def cmd_auth_sessions_list(args: argparse.Namespace) -> int:
    """List active sessions."""
    manager = _get_session_manager()

    user_id = getattr(args, "user_id", None)
    if user_id:
        sessions = manager.get_user_sessions(user_id)
    else:
        # List all sessions
        sessions = [
            s for s in manager._sessions.values()
            if s.is_valid(manager.config.session_idle_timeout_hours)
        ]

    if args.format == "json":
        data = [
            {
                "id": s.id,
                "user_id": s.user_id,
                "ip_address": s.ip_address,
                "user_agent": s.user_agent[:50] if s.user_agent else "",
                "created_at": s.created_at.isoformat(),
                "expires_at": s.expires_at.isoformat(),
                "last_activity_at": s.last_activity_at.isoformat(),
            }
            for s in sessions
        ]
        _output_result(data, "json")
    else:
        headers = ["ID", "User ID", "IP Address", "Created", "Last Activity"]
        rows = [
            [
                s.id[:12] + "...",
                s.user_id[:12] + "...",
                s.ip_address or "-",
                _format_datetime(s.created_at),
                _format_datetime(s.last_activity_at),
            ]
            for s in sessions
        ]
        print(_format_table(headers, rows))
        print(f"\nTotal: {len(sessions)} active sessions")

    return 0


def cmd_auth_sessions_terminate(args: argparse.Namespace) -> int:
    """Terminate a session."""
    manager = _get_session_manager()
    audit = _get_audit_logger()

    if manager.terminate_session(args.session_id):
        audit.log_session_terminated(
            user_id="cli",
            session_id=args.session_id,
            reason=getattr(args, "reason", "Terminated via CLI"),
        )
        print(f"Session {args.session_id} terminated.")
        return 0
    else:
        print(f"Error: Session not found: {args.session_id}")
        return 1


def cmd_auth_sessions_terminate_user(args: argparse.Namespace) -> int:
    """Terminate all sessions for a user."""
    manager = _get_session_manager()

    count = manager.terminate_user_sessions(args.user_id)
    print(f"Terminated {count} sessions for user {args.user_id}.")
    return 0


def cmd_auth_sessions_cleanup(args: argparse.Namespace) -> int:
    """Clean up expired sessions."""
    manager = _get_session_manager()

    count = manager.cleanup_expired()
    print(f"Cleaned up {count} expired sessions.")
    return 0


# =============================================================================
# Role Commands
# =============================================================================

def cmd_auth_roles_list(args: argparse.Namespace) -> int:
    """List available roles."""
    manager = _get_rbac_manager()

    roles = list(manager._roles.values())

    if args.format == "json":
        data = [
            {
                "name": r.name,
                "description": r.description,
                "permissions": sorted(list(r.permissions)),
                "is_system": r.is_system,
            }
            for r in roles
        ]
        _output_result(data, "json")
    else:
        headers = ["Name", "Description", "Permissions", "System"]
        rows = [
            [
                r.name,
                r.description[:40] + "..." if len(r.description) > 40 else r.description,
                str(len(r.permissions)),
                "Yes" if r.is_system else "No",
            ]
            for r in roles
        ]
        print(_format_table(headers, rows))
        print(f"\nTotal: {len(roles)} roles")

    return 0


def cmd_auth_roles_show(args: argparse.Namespace) -> int:
    """Show role details."""
    manager = _get_rbac_manager()

    role = manager.get_role(args.role_name)
    if role is None:
        print(f"Error: Role not found: {args.role_name}")
        return 1

    if args.format == "json":
        _output_result({
            "name": role.name,
            "description": role.description,
            "permissions": sorted(list(role.permissions)),
            "is_system": role.is_system,
            "parent_roles": list(role.parent_roles) if role.parent_roles else [],
        }, "json")
    else:
        print(f"Role: {role.name}")
        print(f"  Description: {role.description}")
        print(f"  System Role: {'Yes' if role.is_system else 'No'}")
        if role.parent_roles:
            print(f"  Inherits From: {', '.join(role.parent_roles)}")
        print(f"  Permissions ({len(role.permissions)}):")
        for perm in sorted(role.permissions):
            print(f"    - {perm}")

    return 0


def cmd_auth_roles_assign(args: argparse.Namespace) -> int:
    """Assign a role to a user."""
    user_manager = _get_user_manager()
    audit = _get_audit_logger()

    try:
        role = UserRole(args.role_name)
    except ValueError:
        print(f"Error: Invalid role '{args.role_name}'")
        print(f"Valid roles: {', '.join(r.value for r in UserRole)}")
        return 1

    try:
        user = user_manager.add_user_role(args.user_id, role)
        audit.log_role_assigned(
            user_id=args.user_id,
            role=args.role_name,
            assigned_by_user_id="cli",
        )
        print(f"Role '{args.role_name}' assigned to user {user.username}.")
        return 0
    except UserNotFoundError:
        print(f"Error: User not found: {args.user_id}")
        return 1


def cmd_auth_roles_revoke(args: argparse.Namespace) -> int:
    """Revoke a role from a user."""
    user_manager = _get_user_manager()
    audit = _get_audit_logger()

    try:
        role = UserRole(args.role_name)
    except ValueError:
        print(f"Error: Invalid role '{args.role_name}'")
        return 1

    try:
        user = user_manager.remove_user_role(args.user_id, role)
        audit.log_role_removed(
            user_id=args.user_id,
            role=args.role_name,
            removed_by_user_id="cli",
        )
        print(f"Role '{args.role_name}' revoked from user {user.username}.")
        return 0
    except UserNotFoundError:
        print(f"Error: User not found: {args.user_id}")
        return 1


# =============================================================================
# Audit Commands
# =============================================================================

def cmd_auth_audit_list(args: argparse.Namespace) -> int:
    """List audit events."""
    audit = _get_audit_logger()

    event_type = None
    if hasattr(args, "event_type") and args.event_type:
        try:
            event_type = AuditEventType(args.event_type)
        except ValueError:
            print(f"Error: Invalid event type '{args.event_type}'")
            return 1

    events = audit.get_events(
        user_id=getattr(args, "user_id", None),
        event_type=event_type,
        status=getattr(args, "status", None),
        limit=getattr(args, "limit", 100),
    )

    if args.format == "json":
        data = [
            {
                "id": e.id,
                "event_type": e.event_type.value,
                "user_id": e.user_id,
                "ip_address": e.ip_address,
                "action": e.action,
                "status": e.status,
                "timestamp": e.timestamp.isoformat(),
            }
            for e in events
        ]
        _output_result(data, "json")
    else:
        headers = ["ID", "Type", "User", "IP", "Action", "Status", "Time"]
        rows = [
            [
                e.id[:8] + "...",
                e.event_type.value[:15],
                e.user_id[:12] + "..." if e.user_id else "-",
                e.ip_address or "-",
                e.action[:15] if e.action else "-",
                e.status,
                _format_datetime(e.timestamp),
            ]
            for e in events
        ]
        print(_format_table(headers, rows))
        print(f"\nTotal: {len(events)} events")

    return 0


def cmd_auth_audit_security(args: argparse.Namespace) -> int:
    """Show security-related audit events."""
    audit = _get_audit_logger()

    hours = getattr(args, "hours", 24)
    events = audit.get_security_events(hours=hours, limit=getattr(args, "limit", 100))

    if args.format == "json":
        data = [
            {
                "id": e.id,
                "event_type": e.event_type.value,
                "user_id": e.user_id,
                "ip_address": e.ip_address,
                "action": e.action,
                "status": e.status,
                "error_message": e.error_message,
                "timestamp": e.timestamp.isoformat(),
            }
            for e in events
        ]
        _output_result(data, "json")
    else:
        print(f"Security Events (last {hours} hours):")
        print()
        headers = ["Type", "User", "IP", "Status", "Error", "Time"]
        rows = [
            [
                e.event_type.value[:20],
                e.user_id[:12] + "..." if e.user_id else "-",
                e.ip_address or "-",
                e.status,
                e.error_message[:20] + "..." if e.error_message else "-",
                _format_datetime(e.timestamp),
            ]
            for e in events
        ]
        print(_format_table(headers, rows))
        print(f"\nTotal: {len(events)} security events")

    return 0


def cmd_auth_audit_failed_logins(args: argparse.Namespace) -> int:
    """Show failed login attempts."""
    audit = _get_audit_logger()

    hours = getattr(args, "hours", 24)
    events = audit.get_failed_logins(hours=hours, limit=getattr(args, "limit", 100))

    if args.format == "json":
        data = [
            {
                "id": e.id,
                "user_id": e.user_id,
                "ip_address": e.ip_address,
                "user_agent": e.user_agent,
                "error_message": e.error_message,
                "timestamp": e.timestamp.isoformat(),
            }
            for e in events
        ]
        _output_result(data, "json")
    else:
        print(f"Failed Login Attempts (last {hours} hours):")
        print()
        headers = ["User", "IP", "Reason", "Time"]
        rows = [
            [
                e.user_id or "-",
                e.ip_address or "-",
                e.error_message[:30] + "..." if e.error_message else "-",
                _format_datetime(e.timestamp),
            ]
            for e in events
        ]
        print(_format_table(headers, rows))
        print(f"\nTotal: {len(events)} failed attempts")

    return 0


def cmd_auth_audit_stats(args: argparse.Namespace) -> int:
    """Show audit statistics."""
    audit = _get_audit_logger()

    stats = audit.get_stats()

    if args.format == "json":
        _output_result(stats, "json")
    else:
        print("Audit Statistics:")
        print(f"  Total Events: {stats['total_events']}")
        print(f"  Events (24h): {stats['events_last_24h']}")
        print(f"  Failed Logins (24h): {stats['failed_logins_24h']}")
        print(f"  Retention: {stats['retention_days']} days")
        print()
        print("Events by Type (24h):")
        for event_type, count in sorted(stats['event_counts_24h'].items()):
            print(f"  {event_type}: {count}")

    return 0


# =============================================================================
# Status Command
# =============================================================================

def cmd_auth_status(args: argparse.Namespace) -> int:
    """Show authentication system status."""
    user_manager = _get_user_manager()
    api_key_manager = _get_api_key_manager()
    session_manager = _get_session_manager()
    audit = _get_audit_logger()

    user_stats = user_manager.get_stats()
    session_stats = session_manager.get_stats()
    audit_stats = audit.get_stats()

    # Count API keys
    all_keys = api_key_manager.list_keys()
    active_keys = sum(1 for k in all_keys if k.status == APIKeyStatus.ACTIVE)

    if args.format == "json":
        _output_result({
            "users": user_stats,
            "api_keys": {
                "total": len(all_keys),
                "active": active_keys,
            },
            "sessions": session_stats,
            "audit": audit_stats,
        }, "json")
    else:
        print("Authentication System Status")
        print("=" * 40)
        print()
        print("Users:")
        print(f"  Total: {user_stats['total_users']}")
        for status, count in user_stats['status_counts'].items():
            print(f"  {status}: {count}")
        print()
        print("API Keys:")
        print(f"  Total: {len(all_keys)}")
        print(f"  Active: {active_keys}")
        print()
        print("Sessions:")
        print(f"  Total: {session_stats['total_sessions']}")
        print(f"  Active: {session_stats['active_sessions']}")
        print(f"  Users with Sessions: {session_stats['users_with_sessions']}")
        print()
        print("Audit:")
        print(f"  Total Events: {audit_stats['total_events']}")
        print(f"  Events (24h): {audit_stats['events_last_24h']}")
        print(f"  Failed Logins (24h): {audit_stats['failed_logins_24h']}")

    return 0


# =============================================================================
# Main Command Router
# =============================================================================

def cmd_auth(args: argparse.Namespace) -> int:
    """Main auth command router."""
    action = getattr(args, "auth_action", None)

    if action is None:
        # Show status by default
        return cmd_auth_status(args)

    # Route to subcommands
    if action == "users":
        sub_action = getattr(args, "users_action", None)
        if sub_action == "list" or sub_action is None:
            return cmd_auth_users_list(args)
        elif sub_action == "create":
            return cmd_auth_users_create(args)
        elif sub_action == "show":
            return cmd_auth_users_show(args)
        elif sub_action == "delete":
            return cmd_auth_users_delete(args)
        elif sub_action == "suspend":
            return cmd_auth_users_suspend(args)
        elif sub_action == "reactivate":
            return cmd_auth_users_reactivate(args)

    elif action == "apikeys":
        sub_action = getattr(args, "apikeys_action", None)
        if sub_action == "list" or sub_action is None:
            return cmd_auth_apikeys_list(args)
        elif sub_action == "create":
            return cmd_auth_apikeys_create(args)
        elif sub_action == "revoke":
            return cmd_auth_apikeys_revoke(args)
        elif sub_action == "rotate":
            return cmd_auth_apikeys_rotate(args)

    elif action == "sessions":
        sub_action = getattr(args, "sessions_action", None)
        if sub_action == "list" or sub_action is None:
            return cmd_auth_sessions_list(args)
        elif sub_action == "terminate":
            return cmd_auth_sessions_terminate(args)
        elif sub_action == "terminate-user":
            return cmd_auth_sessions_terminate_user(args)
        elif sub_action == "cleanup":
            return cmd_auth_sessions_cleanup(args)

    elif action == "roles":
        sub_action = getattr(args, "roles_action", None)
        if sub_action == "list" or sub_action is None:
            return cmd_auth_roles_list(args)
        elif sub_action == "show":
            return cmd_auth_roles_show(args)
        elif sub_action == "assign":
            return cmd_auth_roles_assign(args)
        elif sub_action == "revoke":
            return cmd_auth_roles_revoke(args)

    elif action == "audit":
        sub_action = getattr(args, "audit_action", None)
        if sub_action == "list" or sub_action is None:
            return cmd_auth_audit_list(args)
        elif sub_action == "security":
            return cmd_auth_audit_security(args)
        elif sub_action == "failed-logins":
            return cmd_auth_audit_failed_logins(args)
        elif sub_action == "stats":
            return cmd_auth_audit_stats(args)

    elif action == "status":
        return cmd_auth_status(args)

    print("Unknown auth action. Use 'stance auth --help' for usage.")
    return 1


# =============================================================================
# Parser Setup
# =============================================================================

def add_auth_parser(subparsers: argparse._SubParsersAction) -> None:
    """Add auth command parser."""
    auth_parser = subparsers.add_parser(
        "auth",
        help="Authentication and authorization management",
    )
    auth_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    auth_subparsers = auth_parser.add_subparsers(dest="auth_action")

    # =========================================================================
    # Users subcommand
    # =========================================================================
    users_parser = auth_subparsers.add_parser("users", help="User management")
    users_subparsers = users_parser.add_subparsers(dest="users_action")

    # users list
    users_list_parser = users_subparsers.add_parser("list", help="List users")
    users_list_parser.add_argument(
        "--status",
        choices=["active", "suspended", "pending_verification"],
        help="Filter by status",
    )
    users_list_parser.add_argument(
        "--role",
        choices=["super_admin", "admin", "security_admin", "analyst", "viewer", "api_user", "service_account"],
        help="Filter by role",
    )
    users_list_parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum results (default: 100)",
    )
    users_list_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # users create
    users_create_parser = users_subparsers.add_parser("create", help="Create a user")
    users_create_parser.add_argument(
        "--email",
        required=True,
        help="User email",
    )
    users_create_parser.add_argument(
        "--username",
        required=True,
        help="Username",
    )
    users_create_parser.add_argument(
        "--password",
        required=True,
        help="Password",
    )
    users_create_parser.add_argument(
        "--display-name",
        help="Display name",
    )
    users_create_parser.add_argument(
        "--roles",
        help="Comma-separated roles (e.g., admin,analyst)",
    )
    users_create_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # users show
    users_show_parser = users_subparsers.add_parser("show", help="Show user details")
    users_show_parser.add_argument(
        "user_id",
        help="User ID, email, or username",
    )
    users_show_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # users delete
    users_delete_parser = users_subparsers.add_parser("delete", help="Delete a user")
    users_delete_parser.add_argument(
        "user_id",
        help="User ID",
    )
    users_delete_parser.add_argument(
        "--force",
        action="store_true",
        help="Skip confirmation",
    )

    # users suspend
    users_suspend_parser = users_subparsers.add_parser("suspend", help="Suspend a user")
    users_suspend_parser.add_argument(
        "user_id",
        help="User ID",
    )
    users_suspend_parser.add_argument(
        "--reason",
        help="Suspension reason",
    )

    # users reactivate
    users_reactivate_parser = users_subparsers.add_parser("reactivate", help="Reactivate a user")
    users_reactivate_parser.add_argument(
        "user_id",
        help="User ID",
    )

    # =========================================================================
    # API Keys subcommand
    # =========================================================================
    apikeys_parser = auth_subparsers.add_parser("apikeys", help="API key management")
    apikeys_subparsers = apikeys_parser.add_subparsers(dest="apikeys_action")

    # apikeys list
    apikeys_list_parser = apikeys_subparsers.add_parser("list", help="List API keys")
    apikeys_list_parser.add_argument(
        "--user-id",
        help="Filter by user ID",
    )
    apikeys_list_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # apikeys create
    apikeys_create_parser = apikeys_subparsers.add_parser("create", help="Create an API key")
    apikeys_create_parser.add_argument(
        "--name",
        required=True,
        help="Key name",
    )
    apikeys_create_parser.add_argument(
        "--user-id",
        help="User ID (optional)",
    )
    apikeys_create_parser.add_argument(
        "--scopes",
        help="Comma-separated scopes",
    )
    apikeys_create_parser.add_argument(
        "--expires-days",
        type=int,
        help="Expiration in days",
    )
    apikeys_create_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # apikeys revoke
    apikeys_revoke_parser = apikeys_subparsers.add_parser("revoke", help="Revoke an API key")
    apikeys_revoke_parser.add_argument(
        "key_id",
        help="Key ID",
    )
    apikeys_revoke_parser.add_argument(
        "--reason",
        help="Revocation reason",
    )

    # apikeys rotate
    apikeys_rotate_parser = apikeys_subparsers.add_parser("rotate", help="Rotate an API key")
    apikeys_rotate_parser.add_argument(
        "key_id",
        help="Key ID to rotate",
    )
    apikeys_rotate_parser.add_argument(
        "--expires-days",
        type=int,
        help="New expiration in days",
    )
    apikeys_rotate_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # =========================================================================
    # Sessions subcommand
    # =========================================================================
    sessions_parser = auth_subparsers.add_parser("sessions", help="Session management")
    sessions_subparsers = sessions_parser.add_subparsers(dest="sessions_action")

    # sessions list
    sessions_list_parser = sessions_subparsers.add_parser("list", help="List sessions")
    sessions_list_parser.add_argument(
        "--user-id",
        help="Filter by user ID",
    )
    sessions_list_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # sessions terminate
    sessions_terminate_parser = sessions_subparsers.add_parser("terminate", help="Terminate a session")
    sessions_terminate_parser.add_argument(
        "session_id",
        help="Session ID",
    )
    sessions_terminate_parser.add_argument(
        "--reason",
        help="Termination reason",
    )

    # sessions terminate-user
    sessions_terminate_user_parser = sessions_subparsers.add_parser(
        "terminate-user", help="Terminate all sessions for a user"
    )
    sessions_terminate_user_parser.add_argument(
        "user_id",
        help="User ID",
    )

    # sessions cleanup
    sessions_subparsers.add_parser("cleanup", help="Clean up expired sessions")

    # =========================================================================
    # Roles subcommand
    # =========================================================================
    roles_parser = auth_subparsers.add_parser("roles", help="Role management")
    roles_subparsers = roles_parser.add_subparsers(dest="roles_action")

    # roles list
    roles_list_parser = roles_subparsers.add_parser("list", help="List roles")
    roles_list_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # roles show
    roles_show_parser = roles_subparsers.add_parser("show", help="Show role details")
    roles_show_parser.add_argument(
        "role_name",
        help="Role name",
    )
    roles_show_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # roles assign
    roles_assign_parser = roles_subparsers.add_parser("assign", help="Assign role to user")
    roles_assign_parser.add_argument(
        "user_id",
        help="User ID",
    )
    roles_assign_parser.add_argument(
        "role_name",
        help="Role name",
    )

    # roles revoke
    roles_revoke_parser = roles_subparsers.add_parser("revoke", help="Revoke role from user")
    roles_revoke_parser.add_argument(
        "user_id",
        help="User ID",
    )
    roles_revoke_parser.add_argument(
        "role_name",
        help="Role name",
    )

    # =========================================================================
    # Audit subcommand
    # =========================================================================
    audit_parser = auth_subparsers.add_parser("audit", help="Audit log viewing")
    audit_subparsers = audit_parser.add_subparsers(dest="audit_action")

    # audit list
    audit_list_parser = audit_subparsers.add_parser("list", help="List audit events")
    audit_list_parser.add_argument(
        "--user-id",
        help="Filter by user ID",
    )
    audit_list_parser.add_argument(
        "--event-type",
        help="Filter by event type",
    )
    audit_list_parser.add_argument(
        "--status",
        choices=["success", "failure"],
        help="Filter by status",
    )
    audit_list_parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum results (default: 100)",
    )
    audit_list_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # audit security
    audit_security_parser = audit_subparsers.add_parser("security", help="Security events")
    audit_security_parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Hours to look back (default: 24)",
    )
    audit_security_parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum results (default: 100)",
    )
    audit_security_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # audit failed-logins
    audit_failed_parser = audit_subparsers.add_parser("failed-logins", help="Failed login attempts")
    audit_failed_parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Hours to look back (default: 24)",
    )
    audit_failed_parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum results (default: 100)",
    )
    audit_failed_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # audit stats
    audit_stats_parser = audit_subparsers.add_parser("stats", help="Audit statistics")
    audit_stats_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # =========================================================================
    # Status subcommand
    # =========================================================================
    status_parser = auth_subparsers.add_parser("status", help="Show auth system status")
    status_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
