"""
Session management for Mantissa Stance.

Provides session creation, validation, and lifecycle management.

Part of Phase 92: API Gateway & Authentication
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from stance.auth.models import UserSession

logger = logging.getLogger(__name__)


# =============================================================================
# Exceptions
# =============================================================================

class SessionError(Exception):
    """Base session error."""
    pass


class SessionExpiredError(SessionError):
    """Session has expired."""
    pass


class SessionNotFoundError(SessionError):
    """Session not found."""
    pass


class SessionHijackingError(SessionError):
    """Session context mismatch detected (potential hijacking)."""
    pass


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class SessionConfig:
    """
    Session configuration.

    Attributes:
        session_lifetime_hours: Session lifetime in hours
        session_idle_timeout_hours: Idle timeout in hours
        max_sessions_per_user: Maximum concurrent sessions per user
        secure_cookies: Use secure cookies
        same_site: SameSite cookie attribute
        token_length: Session token length in bytes
        extend_on_activity: Extend session on activity
        bind_to_ip: Require IP address to match for session validation
        bind_to_user_agent: Require User-Agent to match for session validation
    """
    session_lifetime_hours: int = 24
    session_idle_timeout_hours: int = 8
    max_sessions_per_user: int = 5
    secure_cookies: bool = True
    same_site: str = "lax"
    token_length: int = 32
    extend_on_activity: bool = True
    bind_to_ip: bool = False  # Disabled by default due to mobile/VPN users
    bind_to_user_agent: bool = True  # Enabled by default as UA rarely changes


# =============================================================================
# Session Model
# =============================================================================

@dataclass
class Session:
    """Extended session with additional tracking."""
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
    tenant_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if session is expired."""
        return datetime.utcnow() >= self.expires_at

    def is_idle_timeout(self, idle_hours: int) -> bool:
        """Check if session has timed out due to inactivity."""
        # Ensure idle_hours is positive to prevent immediate timeout
        if idle_hours <= 0:
            idle_hours = 1  # Minimum 1 hour idle timeout
        idle_deadline = self.last_activity_at + timedelta(hours=idle_hours)
        return datetime.utcnow() >= idle_deadline

    def is_valid(self, idle_timeout_hours: int = 8) -> bool:
        """Check if session is valid."""
        if not self.is_active:
            return False
        if self.is_expired():
            return False
        # Ensure idle_timeout_hours is positive
        if idle_timeout_hours <= 0:
            idle_timeout_hours = 1  # Minimum 1 hour
        if self.is_idle_timeout(idle_timeout_hours):
            return False
        return True

    def refresh(self, extend_hours: int = 24) -> None:
        """Refresh session."""
        self.last_activity_at = datetime.utcnow()
        self.expires_at = datetime.utcnow() + timedelta(hours=extend_hours)

    def record_activity(self) -> None:
        """Record activity."""
        self.last_activity_at = datetime.utcnow()

    def terminate(self) -> None:
        """Terminate session."""
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
            "tenant_id": self.tenant_id,
        }


# =============================================================================
# Session Manager
# =============================================================================

class SessionManager:
    """
    Session lifecycle manager.

    Handles session creation, validation, and cleanup.
    Thread-safe for multi-threaded environments.
    """

    def __init__(self, config: Optional[SessionConfig] = None):
        """
        Initialize session manager.

        Args:
            config: Session configuration
        """
        self.config = config or SessionConfig()
        self._sessions: Dict[str, Session] = {}
        self._token_index: Dict[str, str] = {}  # token_hash -> session_id
        self._user_sessions: Dict[str, List[str]] = {}  # user_id -> [session_ids]
        self._lock = threading.RLock()  # Reentrant lock for thread safety

    def create_session(
        self,
        user_id: str,
        ip_address: str = "",
        user_agent: str = "",
        device_info: Optional[Dict[str, Any]] = None,
        tenant_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> tuple[Session, str]:
        """
        Create a new session.

        Args:
            user_id: User ID
            ip_address: Client IP
            user_agent: Client user agent
            device_info: Device information
            tenant_id: Tenant ID
            metadata: Additional metadata

        Returns:
            Tuple of (Session, session_token)
        """
        with self._lock:
            # Check session limit
            self._enforce_session_limit(user_id)

            # Generate session token
            session_token = secrets.token_urlsafe(self.config.token_length)
            token_hash = hashlib.sha256(session_token.encode()).hexdigest()

            # Create session
            session = Session(
                id=secrets.token_hex(16),
                user_id=user_id,
                token_hash=token_hash,
                ip_address=ip_address,
                user_agent=user_agent,
                device_info=device_info or {},
                expires_at=datetime.utcnow() + timedelta(hours=self.config.session_lifetime_hours),
                tenant_id=tenant_id,
                metadata=metadata or {},
            )

            # Store session
            self._sessions[session.id] = session
            self._token_index[token_hash] = session.id

            if user_id not in self._user_sessions:
                self._user_sessions[user_id] = []
            self._user_sessions[user_id].append(session.id)

            return session, session_token

    def _enforce_session_limit(self, user_id: str) -> None:
        """Enforce maximum sessions per user."""
        user_session_ids = self._user_sessions.get(user_id, [])

        # Clean up invalid sessions first
        valid_sessions = []
        for sid in user_session_ids:
            session = self._sessions.get(sid)
            if session and session.is_valid(self.config.session_idle_timeout_hours):
                valid_sessions.append(sid)
            elif session:
                self._remove_session(session)

        # If still over limit, remove oldest
        while len(valid_sessions) >= self.config.max_sessions_per_user:
            oldest_id = valid_sessions.pop(0)
            session = self._sessions.get(oldest_id)
            if session:
                self._remove_session(session)

    def validate_session(
        self,
        session_token: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Session:
        """
        Validate a session token.

        Args:
            session_token: Session token to validate
            ip_address: Client IP address for binding validation
            user_agent: Client User-Agent for binding validation

        Returns:
            Valid Session

        Raises:
            SessionNotFoundError: If session not found
            SessionExpiredError: If session expired
            SessionHijackingError: If IP/User-Agent mismatch detected
        """
        with self._lock:
            token_hash = hashlib.sha256(session_token.encode()).hexdigest()

            session_id = self._token_index.get(token_hash)
            if session_id is None:
                raise SessionNotFoundError("Session not found")

            session = self._sessions.get(session_id)
            if session is None:
                raise SessionNotFoundError("Session not found")

            if not session.is_active:
                raise SessionExpiredError("Session has been terminated")

            if session.is_expired():
                raise SessionExpiredError("Session has expired")

            if session.is_idle_timeout(self.config.session_idle_timeout_hours):
                raise SessionExpiredError("Session timed out due to inactivity")

            # Validate IP binding if configured
            if self.config.bind_to_ip and ip_address:
                if session.ip_address and session.ip_address != ip_address:
                    logger.warning(
                        "Session hijacking attempt detected: IP mismatch for session %s "
                        "(expected %s, got %s)",
                        session.id[:8],
                        session.ip_address,
                        ip_address,
                    )
                    # Terminate the session for security
                    session.terminate()
                    raise SessionHijackingError(
                        "Session context mismatch - IP address changed"
                    )

            # Validate User-Agent binding if configured
            if self.config.bind_to_user_agent and user_agent:
                if session.user_agent and session.user_agent != user_agent:
                    logger.warning(
                        "Session hijacking attempt detected: User-Agent mismatch for session %s",
                        session.id[:8],
                    )
                    # Terminate the session for security
                    session.terminate()
                    raise SessionHijackingError(
                        "Session context mismatch - User-Agent changed"
                    )

            # Update activity and optionally extend
            session.record_activity()
            if self.config.extend_on_activity:
                session.expires_at = datetime.utcnow() + timedelta(
                    hours=self.config.session_lifetime_hours
                )

            return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID."""
        with self._lock:
            return self._sessions.get(session_id)

    def get_user_sessions(self, user_id: str) -> List[Session]:
        """Get all sessions for a user."""
        with self._lock:
            session_ids = self._user_sessions.get(user_id, [])
            sessions = []
            for sid in session_ids:
                session = self._sessions.get(sid)
                if session and session.is_valid(self.config.session_idle_timeout_hours):
                    sessions.append(session)
            return sessions

    def terminate_session(self, session_id: str) -> bool:
        """Terminate a session."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False

            session.terminate()
            self._remove_session(session)
            return True

    def terminate_user_sessions(self, user_id: str) -> int:
        """Terminate all sessions for a user."""
        with self._lock:
            session_ids = self._user_sessions.get(user_id, []).copy()
            count = 0
            for sid in session_ids:
                session = self._sessions.get(sid)
                if session:
                    session.terminate()
                    self._remove_session(session)
                    count += 1
            return count

    def _remove_session(self, session: Session) -> None:
        """Remove session from storage."""
        # Remove from main store
        if session.id in self._sessions:
            del self._sessions[session.id]

        # Remove from token index
        if session.token_hash in self._token_index:
            del self._token_index[session.token_hash]

        # Remove from user sessions
        if session.user_id in self._user_sessions:
            self._user_sessions[session.user_id] = [
                sid for sid in self._user_sessions[session.user_id]
                if sid != session.id
            ]

    def cleanup_expired(self) -> int:
        """Clean up expired sessions."""
        with self._lock:
            expired = []
            for session in self._sessions.values():
                if not session.is_valid(self.config.session_idle_timeout_hours):
                    expired.append(session)

            for session in expired:
                self._remove_session(session)

            return len(expired)

    def get_stats(self) -> Dict[str, Any]:
        """Get session manager statistics."""
        with self._lock:
            active = sum(
                1 for s in self._sessions.values()
                if s.is_valid(self.config.session_idle_timeout_hours)
            )
            return {
                "total_sessions": len(self._sessions),
                "active_sessions": active,
                "users_with_sessions": len(self._user_sessions),
                "max_sessions_per_user": self.config.max_sessions_per_user,
                "session_lifetime_hours": self.config.session_lifetime_hours,
            }


def create_session_manager(
    lifetime_hours: int = 24,
    idle_timeout_hours: int = 8,
    max_per_user: int = 5,
) -> SessionManager:
    """Factory function to create session manager."""
    config = SessionConfig(
        session_lifetime_hours=lifetime_hours,
        session_idle_timeout_hours=idle_timeout_hours,
        max_sessions_per_user=max_per_user,
    )
    return SessionManager(config)
