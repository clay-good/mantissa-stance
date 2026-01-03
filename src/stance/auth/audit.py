"""
Audit logging for Mantissa Stance authentication.

Provides comprehensive audit trail for authentication events.

Part of Phase 92: API Gateway & Authentication
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from stance.auth.models import AuditEvent, AuditEventType


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class AuditConfig:
    """
    Audit logging configuration.

    Attributes:
        enabled: Enable audit logging
        log_to_file: Log to file
        log_file_path: Audit log file path
        log_to_console: Log to console
        log_level: Logging level
        include_request_body: Include request body in logs
        include_response_body: Include response body in logs
        sensitive_fields: Fields to redact
        retention_days: Log retention in days
        max_events_in_memory: Maximum events to keep in memory
    """
    enabled: bool = True
    log_to_file: bool = True
    log_file_path: str = "audit.log"
    log_to_console: bool = False
    log_level: str = "INFO"
    include_request_body: bool = False
    include_response_body: bool = False
    sensitive_fields: List[str] = field(default_factory=lambda: [
        "password", "token", "secret", "api_key", "credential",
        "authorization", "cookie", "session"
    ])
    retention_days: int = 90
    max_events_in_memory: int = 10000


# =============================================================================
# Audit Logger
# =============================================================================

class AuditLogger:
    """
    Audit logger for authentication events.

    Provides comprehensive logging for security-relevant events.
    """

    def __init__(
        self,
        config: Optional[AuditConfig] = None,
        event_handler: Optional[Callable[[AuditEvent], None]] = None,
    ):
        """
        Initialize audit logger.

        Args:
            config: Audit configuration
            event_handler: Optional custom event handler
        """
        self.config = config or AuditConfig()
        self.event_handler = event_handler
        self._events: List[AuditEvent] = []
        self._logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        """Set up Python logger."""
        logger = logging.getLogger("stance.auth.audit")
        logger.setLevel(getattr(logging, self.config.log_level.upper()))

        # Remove existing handlers
        logger.handlers = []

        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

        if self.config.log_to_console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        if self.config.log_to_file:
            file_handler = logging.FileHandler(self.config.log_file_path)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        return logger

    def log_event(
        self,
        event_type: AuditEventType,
        user_id: Optional[str] = None,
        ip_address: str = "",
        user_agent: str = "",
        resource_type: str = "",
        resource_id: str = "",
        action: str = "",
        status: str = "success",
        error_message: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        request_id: str = "",
        tenant_id: Optional[str] = None,
    ) -> AuditEvent:
        """
        Log an audit event.

        Args:
            event_type: Type of event
            user_id: User ID (if authenticated)
            ip_address: Client IP address
            user_agent: Client user agent
            resource_type: Type of resource accessed
            resource_id: ID of resource accessed
            action: Action performed
            status: Status of action (success/failure)
            error_message: Error message if failed
            metadata: Additional metadata
            request_id: Request ID for correlation
            tenant_id: Tenant ID

        Returns:
            Created AuditEvent
        """
        if not self.config.enabled:
            return AuditEvent(
                event_type=event_type,
                user_id=user_id,
                ip_address=ip_address,
            )

        # Redact sensitive fields from metadata
        safe_metadata = self._redact_sensitive(metadata or {})

        event = AuditEvent(
            event_type=event_type,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            status=status,
            error_message=error_message,
            metadata=safe_metadata,
            request_id=request_id,
            tenant_id=tenant_id,
        )

        # Store event
        self._store_event(event)

        # Log to Python logger
        self._log_to_logger(event)

        # Call custom handler
        if self.event_handler:
            try:
                self.event_handler(event)
            except Exception as e:
                self._logger.error(f"Event handler error: {e}")

        return event

    def _redact_sensitive(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive fields from data."""
        result = {}
        for key, value in data.items():
            key_lower = key.lower()
            if any(field in key_lower for field in self.config.sensitive_fields):
                result[key] = "[REDACTED]"
            elif isinstance(value, dict):
                result[key] = self._redact_sensitive(value)
            else:
                result[key] = value
        return result

    def _store_event(self, event: AuditEvent) -> None:
        """Store event in memory."""
        self._events.append(event)

        # Enforce memory limit
        if len(self._events) > self.config.max_events_in_memory:
            # Remove oldest events
            excess = len(self._events) - self.config.max_events_in_memory
            self._events = self._events[excess:]

    def _log_to_logger(self, event: AuditEvent) -> None:
        """Log event to Python logger."""
        log_data = {
            "event_id": event.id,
            "event_type": event.event_type.value,
            "user_id": event.user_id,
            "ip_address": event.ip_address,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "action": event.action,
            "status": event.status,
            "request_id": event.request_id,
            "tenant_id": event.tenant_id,
        }

        if event.error_message:
            log_data["error"] = event.error_message

        message = json.dumps(log_data)

        if event.status == "failure":
            self._logger.warning(message)
        else:
            self._logger.info(message)

    # =========================================================================
    # Convenience Methods
    # =========================================================================

    def log_login_success(
        self,
        user_id: str,
        ip_address: str,
        user_agent: str = "",
        auth_method: str = "password",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log successful login."""
        return self.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            action="login",
            status="success",
            metadata={**(metadata or {}), "auth_method": auth_method},
        )

    def log_login_failure(
        self,
        user_id: Optional[str],
        ip_address: str,
        user_agent: str = "",
        reason: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log failed login attempt."""
        return self.log_event(
            event_type=AuditEventType.LOGIN_FAILURE,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            action="login",
            status="failure",
            error_message=reason,
            metadata=metadata,
        )

    def log_logout(
        self,
        user_id: str,
        ip_address: str,
        user_agent: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log logout."""
        return self.log_event(
            event_type=AuditEventType.LOGOUT,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            action="logout",
            status="success",
            metadata=metadata,
        )

    def log_token_issued(
        self,
        user_id: str,
        ip_address: str,
        token_type: str = "access",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log token issuance."""
        return self.log_event(
            event_type=AuditEventType.TOKEN_ISSUED,
            user_id=user_id,
            ip_address=ip_address,
            action="token_issue",
            status="success",
            metadata={**(metadata or {}), "token_type": token_type},
        )

    def log_token_revoked(
        self,
        user_id: str,
        ip_address: str,
        reason: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log token revocation."""
        return self.log_event(
            event_type=AuditEventType.TOKEN_REVOKED,
            user_id=user_id,
            ip_address=ip_address,
            action="token_revoke",
            status="success",
            metadata={**(metadata or {}), "reason": reason},
        )

    def log_api_key_created(
        self,
        user_id: str,
        key_id: str,
        key_name: str,
        ip_address: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log API key creation."""
        return self.log_event(
            event_type=AuditEventType.API_KEY_CREATED,
            user_id=user_id,
            ip_address=ip_address,
            resource_type="api_key",
            resource_id=key_id,
            action="create",
            status="success",
            metadata={**(metadata or {}), "key_name": key_name},
        )

    def log_api_key_revoked(
        self,
        user_id: str,
        key_id: str,
        ip_address: str = "",
        reason: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log API key revocation."""
        return self.log_event(
            event_type=AuditEventType.API_KEY_REVOKED,
            user_id=user_id,
            ip_address=ip_address,
            resource_type="api_key",
            resource_id=key_id,
            action="revoke",
            status="success",
            metadata={**(metadata or {}), "reason": reason},
        )

    def log_permission_denied(
        self,
        user_id: str,
        permission: str,
        resource_type: str = "",
        resource_id: str = "",
        ip_address: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log permission denied event."""
        return self.log_event(
            event_type=AuditEventType.PERMISSION_DENIED,
            user_id=user_id,
            ip_address=ip_address,
            resource_type=resource_type,
            resource_id=resource_id,
            action=permission,
            status="failure",
            error_message=f"Permission denied: {permission}",
            metadata=metadata,
        )

    def log_password_change(
        self,
        user_id: str,
        ip_address: str,
        success: bool = True,
        reason: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log password change."""
        return self.log_event(
            event_type=AuditEventType.PASSWORD_CHANGED,
            user_id=user_id,
            ip_address=ip_address,
            action="password_change",
            status="success" if success else "failure",
            error_message=reason if not success else "",
            metadata=metadata,
        )

    def log_user_created(
        self,
        created_user_id: str,
        created_by_user_id: str,
        ip_address: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log user creation."""
        return self.log_event(
            event_type=AuditEventType.USER_CREATED,
            user_id=created_by_user_id,
            ip_address=ip_address,
            resource_type="user",
            resource_id=created_user_id,
            action="create",
            status="success",
            metadata=metadata,
        )

    def log_user_deleted(
        self,
        deleted_user_id: str,
        deleted_by_user_id: str,
        ip_address: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log user deletion."""
        return self.log_event(
            event_type=AuditEventType.USER_DELETED,
            user_id=deleted_by_user_id,
            ip_address=ip_address,
            resource_type="user",
            resource_id=deleted_user_id,
            action="delete",
            status="success",
            metadata=metadata,
        )

    def log_role_assigned(
        self,
        user_id: str,
        role: str,
        assigned_by_user_id: str,
        ip_address: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log role assignment."""
        return self.log_event(
            event_type=AuditEventType.ROLE_ASSIGNED,
            user_id=assigned_by_user_id,
            ip_address=ip_address,
            resource_type="user",
            resource_id=user_id,
            action="assign_role",
            status="success",
            metadata={**(metadata or {}), "role": role},
        )

    def log_role_removed(
        self,
        user_id: str,
        role: str,
        removed_by_user_id: str,
        ip_address: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log role removal."""
        return self.log_event(
            event_type=AuditEventType.ROLE_REMOVED,
            user_id=removed_by_user_id,
            ip_address=ip_address,
            resource_type="user",
            resource_id=user_id,
            action="remove_role",
            status="success",
            metadata={**(metadata or {}), "role": role},
        )

    def log_session_created(
        self,
        user_id: str,
        session_id: str,
        ip_address: str,
        user_agent: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log session creation."""
        return self.log_event(
            event_type=AuditEventType.SESSION_CREATED,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            resource_type="session",
            resource_id=session_id,
            action="create",
            status="success",
            metadata=metadata,
        )

    def log_session_terminated(
        self,
        user_id: str,
        session_id: str,
        ip_address: str = "",
        reason: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log session termination."""
        return self.log_event(
            event_type=AuditEventType.SESSION_TERMINATED,
            user_id=user_id,
            ip_address=ip_address,
            resource_type="session",
            resource_id=session_id,
            action="terminate",
            status="success",
            metadata={**(metadata or {}), "reason": reason},
        )

    # =========================================================================
    # Query Methods
    # =========================================================================

    def get_events(
        self,
        user_id: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        ip_address: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """
        Query audit events.

        Args:
            user_id: Filter by user ID
            event_type: Filter by event type
            start_time: Filter by start time
            end_time: Filter by end time
            ip_address: Filter by IP address
            status: Filter by status
            limit: Maximum events to return

        Returns:
            List of matching AuditEvents
        """
        results = []

        for event in reversed(self._events):
            if user_id and event.user_id != user_id:
                continue
            if event_type and event.event_type != event_type:
                continue
            if start_time and event.timestamp < start_time:
                continue
            if end_time and event.timestamp > end_time:
                continue
            if ip_address and event.ip_address != ip_address:
                continue
            if status and event.status != status:
                continue

            results.append(event)

            if len(results) >= limit:
                break

        return results

    def get_user_activity(
        self,
        user_id: str,
        days: int = 30,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """Get recent activity for a user."""
        start_time = datetime.utcnow() - timedelta(days=days)
        return self.get_events(
            user_id=user_id,
            start_time=start_time,
            limit=limit,
        )

    def get_failed_logins(
        self,
        hours: int = 24,
        ip_address: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """Get failed login attempts."""
        start_time = datetime.utcnow() - timedelta(hours=hours)
        return self.get_events(
            event_type=AuditEventType.LOGIN_FAILURE,
            start_time=start_time,
            ip_address=ip_address,
            limit=limit,
        )

    def get_security_events(
        self,
        hours: int = 24,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """Get security-relevant events."""
        start_time = datetime.utcnow() - timedelta(hours=hours)
        security_types = {
            AuditEventType.LOGIN_FAILURE,
            AuditEventType.PERMISSION_DENIED,
            AuditEventType.TOKEN_REVOKED,
            AuditEventType.API_KEY_REVOKED,
            AuditEventType.SESSION_TERMINATED,
            AuditEventType.PASSWORD_CHANGED,
        }

        results = []
        for event in reversed(self._events):
            if event.timestamp < start_time:
                continue
            if event.event_type in security_types:
                results.append(event)
                if len(results) >= limit:
                    break

        return results

    def cleanup_old_events(self) -> int:
        """Remove events older than retention period."""
        cutoff = datetime.utcnow() - timedelta(days=self.config.retention_days)
        original_count = len(self._events)
        self._events = [e for e in self._events if e.timestamp >= cutoff]
        return original_count - len(self._events)

    def get_stats(self) -> Dict[str, Any]:
        """Get audit statistics."""
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)

        events_24h = [e for e in self._events if e.timestamp >= last_24h]

        event_counts = {}
        for event in events_24h:
            event_type = event.event_type.value
            event_counts[event_type] = event_counts.get(event_type, 0) + 1

        failed_logins_24h = sum(
            1 for e in events_24h
            if e.event_type == AuditEventType.LOGIN_FAILURE
        )

        return {
            "total_events": len(self._events),
            "events_last_24h": len(events_24h),
            "event_counts_24h": event_counts,
            "failed_logins_24h": failed_logins_24h,
            "retention_days": self.config.retention_days,
            "max_events_in_memory": self.config.max_events_in_memory,
        }


def create_audit_logger(
    log_file_path: str = "audit.log",
    log_to_console: bool = False,
    retention_days: int = 90,
    event_handler: Optional[Callable[[AuditEvent], None]] = None,
) -> AuditLogger:
    """Factory function to create audit logger."""
    config = AuditConfig(
        log_file_path=log_file_path,
        log_to_console=log_to_console,
        retention_days=retention_days,
    )
    return AuditLogger(config, event_handler)
