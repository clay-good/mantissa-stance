"""
Dashboard embedding and sharing system for Mantissa Stance.

Provides secure dashboard embedding, public/private sharing,
embed tokens, access controls, and iframe integration.

Part of Phase 94: Enhanced Visualization
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlencode, quote


# =============================================================================
# Embedding Enums
# =============================================================================

class ShareType(Enum):
    """Types of sharing."""
    PRIVATE = "private"
    INTERNAL = "internal"  # Within organization
    PUBLIC = "public"
    EMBED = "embed"


class AccessLevel(Enum):
    """Access levels for shared dashboards."""
    VIEW = "view"
    INTERACT = "interact"  # View + drill-down, filter
    COMMENT = "comment"
    EDIT = "edit"
    ADMIN = "admin"


class EmbedMode(Enum):
    """Embedding display modes."""
    FULL = "full"  # Full dashboard
    COMPACT = "compact"  # Minimal chrome
    WIDGET = "widget"  # Single widget
    KIOSK = "kiosk"  # Full screen, no controls


class TokenType(Enum):
    """Types of access tokens."""
    EMBED = "embed"
    API = "api"
    SHARE_LINK = "share_link"
    TEMPORARY = "temporary"


# =============================================================================
# Sharing and Access Control
# =============================================================================

@dataclass
class SharePermission:
    """
    Permission granted to a user or group.

    Defines what actions are allowed on a shared dashboard.
    """
    id: str = ""
    grantee_type: str = ""  # "user", "group", "email", "domain", "anyone"
    grantee_id: str = ""  # user ID, group ID, email, domain
    access_level: AccessLevel = AccessLevel.VIEW
    granted_by: str = ""
    granted_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    conditions: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:8]

    def is_valid(self) -> bool:
        """Check if permission is still valid."""
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        return True

    def can_view(self) -> bool:
        """Check if permission allows viewing."""
        return self.access_level in (
            AccessLevel.VIEW,
            AccessLevel.INTERACT,
            AccessLevel.COMMENT,
            AccessLevel.EDIT,
            AccessLevel.ADMIN,
        )

    def can_interact(self) -> bool:
        """Check if permission allows interaction."""
        return self.access_level in (
            AccessLevel.INTERACT,
            AccessLevel.COMMENT,
            AccessLevel.EDIT,
            AccessLevel.ADMIN,
        )

    def can_edit(self) -> bool:
        """Check if permission allows editing."""
        return self.access_level in (
            AccessLevel.EDIT,
            AccessLevel.ADMIN,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "grantee_type": self.grantee_type,
            "grantee_id": self.grantee_id,
            "access_level": self.access_level.value,
            "granted_by": self.granted_by,
            "granted_at": self.granted_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_valid": self.is_valid(),
        }


@dataclass
class ShareSettings:
    """
    Sharing settings for a dashboard.

    Controls who can access and how.
    """
    dashboard_id: str = ""
    share_type: ShareType = ShareType.PRIVATE
    permissions: List[SharePermission] = field(default_factory=list)
    allow_embedding: bool = False
    allow_download: bool = False
    allow_print: bool = True
    require_authentication: bool = True
    password_protected: bool = False
    password_hash: str = ""
    allowed_domains: List[str] = field(default_factory=list)
    blocked_domains: List[str] = field(default_factory=list)
    ip_whitelist: List[str] = field(default_factory=list)
    max_views: Optional[int] = None
    current_views: int = 0
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def add_permission(self, permission: SharePermission) -> None:
        """Add a permission."""
        self.permissions.append(permission)
        self.updated_at = datetime.utcnow()

    def remove_permission(self, permission_id: str) -> bool:
        """Remove a permission by ID."""
        for i, p in enumerate(self.permissions):
            if p.id == permission_id:
                self.permissions.pop(i)
                self.updated_at = datetime.utcnow()
                return True
        return False

    def get_permission(self, grantee_id: str) -> Optional[SharePermission]:
        """Get permission for a specific grantee."""
        for p in self.permissions:
            if p.grantee_id == grantee_id and p.is_valid():
                return p
        return None

    def check_access(
        self,
        user_id: Optional[str] = None,
        email: Optional[str] = None,
        groups: Optional[List[str]] = None,
        domain: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Optional[AccessLevel]:
        """
        Check access level for given credentials.

        Returns highest valid access level or None if no access.
        """
        # Check IP whitelist first if configured
        if self.ip_whitelist:
            if not ip_address or ip_address not in self.ip_whitelist:
                return None

        # Public access
        if self.share_type == ShareType.PUBLIC:
            return AccessLevel.VIEW

        # Check permissions
        access_levels = []

        for permission in self.permissions:
            if not permission.is_valid():
                continue

            if permission.grantee_type == "anyone":
                access_levels.append(permission.access_level)

            elif permission.grantee_type == "user" and user_id:
                if permission.grantee_id == user_id:
                    access_levels.append(permission.access_level)

            elif permission.grantee_type == "email" and email:
                if permission.grantee_id.lower() == email.lower():
                    access_levels.append(permission.access_level)

            elif permission.grantee_type == "group" and groups:
                if permission.grantee_id in groups:
                    access_levels.append(permission.access_level)

            elif permission.grantee_type == "domain" and domain:
                if permission.grantee_id.lower() == domain.lower():
                    access_levels.append(permission.access_level)
                elif email and email.lower().endswith(f"@{permission.grantee_id.lower()}"):
                    access_levels.append(permission.access_level)

        if not access_levels:
            return None

        # Return highest access level
        level_priority = {
            AccessLevel.VIEW: 1,
            AccessLevel.INTERACT: 2,
            AccessLevel.COMMENT: 3,
            AccessLevel.EDIT: 4,
            AccessLevel.ADMIN: 5,
        }
        return max(access_levels, key=lambda l: level_priority.get(l, 0))

    def record_view(self) -> bool:
        """Record a view. Returns False if max views exceeded."""
        if self.max_views and self.current_views >= self.max_views:
            return False
        self.current_views += 1
        return True

    def set_password(self, password: str) -> None:
        """Set password protection."""
        salt = secrets.token_hex(16)
        hash_input = f"{salt}{password}".encode()
        self.password_hash = f"{salt}:{hashlib.sha256(hash_input).hexdigest()}"
        self.password_protected = True

    def verify_password(self, password: str) -> bool:
        """Verify password."""
        if not self.password_protected or not self.password_hash:
            return True

        try:
            salt, stored_hash = self.password_hash.split(":")
            hash_input = f"{salt}{password}".encode()
            computed_hash = hashlib.sha256(hash_input).hexdigest()
            return hmac.compare_digest(stored_hash, computed_hash)
        except Exception:
            return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "dashboard_id": self.dashboard_id,
            "share_type": self.share_type.value,
            "permissions": [p.to_dict() for p in self.permissions],
            "allow_embedding": self.allow_embedding,
            "allow_download": self.allow_download,
            "allow_print": self.allow_print,
            "require_authentication": self.require_authentication,
            "password_protected": self.password_protected,
            "allowed_domains": self.allowed_domains,
            "max_views": self.max_views,
            "current_views": self.current_views,
        }


# =============================================================================
# Embed Token System
# =============================================================================

@dataclass
class EmbedToken:
    """
    Token for embedding dashboards.

    Provides secure, revocable access for embedded dashboards.
    """
    id: str = ""
    token: str = ""
    dashboard_id: str = ""
    widget_id: Optional[str] = None  # For single widget embeds
    token_type: TokenType = TokenType.EMBED
    access_level: AccessLevel = AccessLevel.VIEW
    embed_mode: EmbedMode = EmbedMode.FULL
    created_by: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    use_count: int = 0
    max_uses: Optional[int] = None
    allowed_origins: List[str] = field(default_factory=list)
    allowed_referers: List[str] = field(default_factory=list)
    ip_restrictions: List[str] = field(default_factory=list)
    filters: Dict[str, Any] = field(default_factory=dict)  # Pre-applied filters
    custom_css: str = ""
    hide_controls: bool = False
    hide_title: bool = False
    theme_override: Optional[str] = None
    revoked: bool = False
    revoked_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.token:
            self.token = secrets.token_urlsafe(32)

    def is_valid(self) -> bool:
        """Check if token is valid."""
        if self.revoked:
            return False
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        if self.max_uses and self.use_count >= self.max_uses:
            return False
        return True

    def validate_origin(self, origin: str) -> bool:
        """Validate request origin."""
        if not self.allowed_origins:
            return True  # No restrictions
        return any(
            self._match_origin(origin, allowed)
            for allowed in self.allowed_origins
        )

    def validate_referer(self, referer: str) -> bool:
        """Validate request referer."""
        if not self.allowed_referers:
            return True  # No restrictions
        return any(
            referer.startswith(allowed)
            for allowed in self.allowed_referers
        )

    def validate_ip(self, ip: str) -> bool:
        """Validate IP address."""
        if not self.ip_restrictions:
            return True  # No restrictions
        return ip in self.ip_restrictions

    def _match_origin(self, origin: str, pattern: str) -> bool:
        """Match origin against pattern (supports wildcards)."""
        if pattern == "*":
            return True
        if pattern.startswith("*."):
            # Wildcard subdomain
            domain = pattern[2:]
            return origin.endswith(domain) or origin.endswith(f".{domain}")
        return origin == pattern

    def record_use(self, ip: Optional[str] = None) -> bool:
        """Record token usage. Returns False if max uses exceeded."""
        if self.max_uses and self.use_count >= self.max_uses:
            return False
        self.use_count += 1
        self.last_used_at = datetime.utcnow()
        return True

    def revoke(self) -> None:
        """Revoke the token."""
        self.revoked = True
        self.revoked_at = datetime.utcnow()

    def get_embed_url(self, base_url: str) -> str:
        """Generate embed URL."""
        params = {
            "token": self.token,
            "mode": self.embed_mode.value,
        }
        if self.hide_controls:
            params["controls"] = "false"
        if self.hide_title:
            params["title"] = "false"
        if self.theme_override:
            params["theme"] = self.theme_override

        if self.widget_id:
            path = f"/embed/widget/{self.widget_id}"
        else:
            path = f"/embed/dashboard/{self.dashboard_id}"

        return f"{base_url}{path}?{urlencode(params)}"

    def get_iframe_html(
        self,
        base_url: str,
        width: str = "100%",
        height: str = "600px",
    ) -> str:
        """Generate iframe HTML for embedding."""
        url = self.get_embed_url(base_url)
        return (
            f'<iframe src="{url}" '
            f'width="{width}" height="{height}" '
            f'frameborder="0" allowfullscreen '
            f'sandbox="allow-scripts allow-same-origin allow-popups">'
            f'</iframe>'
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (excludes sensitive token)."""
        return {
            "id": self.id,
            "dashboard_id": self.dashboard_id,
            "widget_id": self.widget_id,
            "token_type": self.token_type.value,
            "access_level": self.access_level.value,
            "embed_mode": self.embed_mode.value,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "use_count": self.use_count,
            "max_uses": self.max_uses,
            "allowed_origins": self.allowed_origins,
            "is_valid": self.is_valid(),
            "revoked": self.revoked,
        }


# =============================================================================
# Share Link System
# =============================================================================

@dataclass
class ShareLink:
    """
    Shareable link for dashboard access.

    Provides URL-based sharing with optional authentication.
    """
    id: str = ""
    short_code: str = ""  # Short URL code
    dashboard_id: str = ""
    access_level: AccessLevel = AccessLevel.VIEW
    created_by: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    password_hash: str = ""
    require_login: bool = False
    allowed_emails: List[str] = field(default_factory=list)
    allowed_domains: List[str] = field(default_factory=list)
    max_uses: Optional[int] = None
    use_count: int = 0
    active: bool = True
    filters: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.short_code:
            self.short_code = secrets.token_urlsafe(8)

    def is_valid(self) -> bool:
        """Check if link is valid."""
        if not self.active:
            return False
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        if self.max_uses and self.use_count >= self.max_uses:
            return False
        return True

    def check_email_access(self, email: str) -> bool:
        """Check if email has access."""
        if not self.allowed_emails and not self.allowed_domains:
            return True  # No restrictions

        email_lower = email.lower()

        # Check specific emails
        if email_lower in [e.lower() for e in self.allowed_emails]:
            return True

        # Check domains
        for domain in self.allowed_domains:
            if email_lower.endswith(f"@{domain.lower()}"):
                return True

        return False

    def set_password(self, password: str) -> None:
        """Set password for link."""
        salt = secrets.token_hex(16)
        hash_input = f"{salt}{password}".encode()
        self.password_hash = f"{salt}:{hashlib.sha256(hash_input).hexdigest()}"

    def verify_password(self, password: str) -> bool:
        """Verify password."""
        if not self.password_hash:
            return True  # No password set

        try:
            salt, stored_hash = self.password_hash.split(":")
            hash_input = f"{salt}{password}".encode()
            computed_hash = hashlib.sha256(hash_input).hexdigest()
            return hmac.compare_digest(stored_hash, computed_hash)
        except Exception:
            return False

    def record_use(self) -> bool:
        """Record link usage."""
        if self.max_uses and self.use_count >= self.max_uses:
            return False
        self.use_count += 1
        return True

    def deactivate(self) -> None:
        """Deactivate the link."""
        self.active = False

    def get_url(self, base_url: str) -> str:
        """Get the full share URL."""
        return f"{base_url}/share/{self.short_code}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "short_code": self.short_code,
            "dashboard_id": self.dashboard_id,
            "access_level": self.access_level.value,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "has_password": bool(self.password_hash),
            "require_login": self.require_login,
            "max_uses": self.max_uses,
            "use_count": self.use_count,
            "is_valid": self.is_valid(),
            "active": self.active,
        }


# =============================================================================
# Embedding Manager
# =============================================================================

class EmbeddingManager:
    """
    Manages dashboard embedding and sharing.

    Provides token management, share link creation, and access validation.
    """

    def __init__(self, signing_key: Optional[str] = None):
        self.signing_key = signing_key or secrets.token_hex(32)
        self.share_settings: Dict[str, ShareSettings] = {}
        self.embed_tokens: Dict[str, EmbedToken] = {}
        self.share_links: Dict[str, ShareLink] = {}
        self.token_by_value: Dict[str, str] = {}  # token value -> token id
        self.link_by_code: Dict[str, str] = {}  # short code -> link id

    def get_share_settings(self, dashboard_id: str) -> ShareSettings:
        """Get or create share settings for a dashboard."""
        if dashboard_id not in self.share_settings:
            self.share_settings[dashboard_id] = ShareSettings(
                dashboard_id=dashboard_id
            )
        return self.share_settings[dashboard_id]

    def update_share_settings(
        self,
        dashboard_id: str,
        settings: ShareSettings
    ) -> None:
        """Update share settings."""
        settings.dashboard_id = dashboard_id
        settings.updated_at = datetime.utcnow()
        self.share_settings[dashboard_id] = settings

    def share_with_user(
        self,
        dashboard_id: str,
        user_id: str,
        access_level: AccessLevel,
        granted_by: str,
        expires_at: Optional[datetime] = None,
    ) -> SharePermission:
        """Share dashboard with a user."""
        settings = self.get_share_settings(dashboard_id)

        permission = SharePermission(
            grantee_type="user",
            grantee_id=user_id,
            access_level=access_level,
            granted_by=granted_by,
            expires_at=expires_at,
        )

        # Remove existing permission for same user
        settings.permissions = [
            p for p in settings.permissions
            if not (p.grantee_type == "user" and p.grantee_id == user_id)
        ]
        settings.add_permission(permission)

        return permission

    def share_with_email(
        self,
        dashboard_id: str,
        email: str,
        access_level: AccessLevel,
        granted_by: str,
        expires_at: Optional[datetime] = None,
    ) -> SharePermission:
        """Share dashboard with an email."""
        settings = self.get_share_settings(dashboard_id)

        permission = SharePermission(
            grantee_type="email",
            grantee_id=email.lower(),
            access_level=access_level,
            granted_by=granted_by,
            expires_at=expires_at,
        )

        settings.add_permission(permission)
        return permission

    def share_with_domain(
        self,
        dashboard_id: str,
        domain: str,
        access_level: AccessLevel,
        granted_by: str,
    ) -> SharePermission:
        """Share dashboard with all users in a domain."""
        settings = self.get_share_settings(dashboard_id)

        permission = SharePermission(
            grantee_type="domain",
            grantee_id=domain.lower(),
            access_level=access_level,
            granted_by=granted_by,
        )

        settings.add_permission(permission)
        return permission

    def make_public(self, dashboard_id: str) -> None:
        """Make dashboard publicly accessible."""
        settings = self.get_share_settings(dashboard_id)
        settings.share_type = ShareType.PUBLIC

    def make_private(self, dashboard_id: str) -> None:
        """Make dashboard private."""
        settings = self.get_share_settings(dashboard_id)
        settings.share_type = ShareType.PRIVATE

    def check_access(
        self,
        dashboard_id: str,
        user_id: Optional[str] = None,
        email: Optional[str] = None,
        groups: Optional[List[str]] = None,
        ip_address: Optional[str] = None,
    ) -> Optional[AccessLevel]:
        """Check access level for dashboard."""
        settings = self.get_share_settings(dashboard_id)

        domain = None
        if email and "@" in email:
            domain = email.split("@")[1]

        return settings.check_access(
            user_id=user_id,
            email=email,
            groups=groups,
            domain=domain,
            ip_address=ip_address,
        )

    def create_embed_token(
        self,
        dashboard_id: str,
        created_by: str,
        widget_id: Optional[str] = None,
        access_level: AccessLevel = AccessLevel.VIEW,
        embed_mode: EmbedMode = EmbedMode.FULL,
        expires_in: Optional[timedelta] = None,
        allowed_origins: Optional[List[str]] = None,
        max_uses: Optional[int] = None,
        filters: Optional[Dict[str, Any]] = None,
        hide_controls: bool = False,
        hide_title: bool = False,
        theme: Optional[str] = None,
    ) -> EmbedToken:
        """Create an embed token for a dashboard."""
        token = EmbedToken(
            dashboard_id=dashboard_id,
            widget_id=widget_id,
            access_level=access_level,
            embed_mode=embed_mode,
            created_by=created_by,
            expires_at=datetime.utcnow() + expires_in if expires_in else None,
            allowed_origins=allowed_origins or [],
            max_uses=max_uses,
            filters=filters or {},
            hide_controls=hide_controls,
            hide_title=hide_title,
            theme_override=theme,
        )

        self.embed_tokens[token.id] = token
        self.token_by_value[token.token] = token.id

        return token

    def validate_embed_token(
        self,
        token_value: str,
        origin: Optional[str] = None,
        referer: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> Optional[EmbedToken]:
        """Validate an embed token."""
        token_id = self.token_by_value.get(token_value)
        if not token_id:
            return None

        token = self.embed_tokens.get(token_id)
        if not token or not token.is_valid():
            return None

        # Validate origin
        if origin and not token.validate_origin(origin):
            return None

        # Validate referer
        if referer and not token.validate_referer(referer):
            return None

        # Validate IP
        if ip and not token.validate_ip(ip):
            return None

        # Record usage
        token.record_use(ip)

        return token

    def revoke_embed_token(self, token_id: str) -> bool:
        """Revoke an embed token."""
        token = self.embed_tokens.get(token_id)
        if not token:
            return False

        token.revoke()
        return True

    def get_embed_tokens(self, dashboard_id: str) -> List[EmbedToken]:
        """Get all embed tokens for a dashboard."""
        return [
            t for t in self.embed_tokens.values()
            if t.dashboard_id == dashboard_id
        ]

    def create_share_link(
        self,
        dashboard_id: str,
        created_by: str,
        access_level: AccessLevel = AccessLevel.VIEW,
        expires_in: Optional[timedelta] = None,
        password: Optional[str] = None,
        require_login: bool = False,
        allowed_emails: Optional[List[str]] = None,
        allowed_domains: Optional[List[str]] = None,
        max_uses: Optional[int] = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> ShareLink:
        """Create a share link for a dashboard."""
        link = ShareLink(
            dashboard_id=dashboard_id,
            access_level=access_level,
            created_by=created_by,
            expires_at=datetime.utcnow() + expires_in if expires_in else None,
            require_login=require_login,
            allowed_emails=allowed_emails or [],
            allowed_domains=allowed_domains or [],
            max_uses=max_uses,
            filters=filters or {},
        )

        if password:
            link.set_password(password)

        self.share_links[link.id] = link
        self.link_by_code[link.short_code] = link.id

        # Update share settings
        settings = self.get_share_settings(dashboard_id)
        if settings.share_type == ShareType.PRIVATE:
            settings.share_type = ShareType.INTERNAL

        return link

    def validate_share_link(
        self,
        short_code: str,
        password: Optional[str] = None,
        email: Optional[str] = None,
    ) -> Optional[ShareLink]:
        """Validate a share link."""
        link_id = self.link_by_code.get(short_code)
        if not link_id:
            return None

        link = self.share_links.get(link_id)
        if not link or not link.is_valid():
            return None

        # Verify password if set
        if link.password_hash and not link.verify_password(password or ""):
            return None

        # Check email restrictions
        if email and not link.check_email_access(email):
            return None

        # Record usage
        link.record_use()

        return link

    def deactivate_share_link(self, link_id: str) -> bool:
        """Deactivate a share link."""
        link = self.share_links.get(link_id)
        if not link:
            return False

        link.deactivate()
        return True

    def get_share_links(self, dashboard_id: str) -> List[ShareLink]:
        """Get all share links for a dashboard."""
        return [
            l for l in self.share_links.values()
            if l.dashboard_id == dashboard_id
        ]

    def generate_signed_url(
        self,
        dashboard_id: str,
        expires_in: timedelta = timedelta(hours=1),
        user_id: Optional[str] = None,
    ) -> str:
        """Generate a signed URL for temporary access."""
        expires_at = int((datetime.utcnow() + expires_in).timestamp())

        payload = {
            "d": dashboard_id,
            "e": expires_at,
        }
        if user_id:
            payload["u"] = user_id

        payload_json = json.dumps(payload, separators=(",", ":"))
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode()

        signature = hmac.new(
            self.signing_key.encode(),
            payload_b64.encode(),
            hashlib.sha256
        ).hexdigest()[:16]

        return f"{payload_b64}.{signature}"

    def validate_signed_url(self, signed_data: str) -> Optional[Dict[str, Any]]:
        """Validate a signed URL."""
        try:
            parts = signed_data.split(".")
            if len(parts) != 2:
                return None

            payload_b64, signature = parts

            # Verify signature
            expected_sig = hmac.new(
                self.signing_key.encode(),
                payload_b64.encode(),
                hashlib.sha256
            ).hexdigest()[:16]

            if not hmac.compare_digest(signature, expected_sig):
                return None

            # Decode payload
            payload_json = base64.urlsafe_b64decode(payload_b64).decode()
            payload = json.loads(payload_json)

            # Check expiration
            expires_at = payload.get("e", 0)
            if datetime.utcnow().timestamp() > expires_at:
                return None

            return {
                "dashboard_id": payload.get("d"),
                "user_id": payload.get("u"),
                "expires_at": datetime.fromtimestamp(expires_at),
            }
        except Exception:
            return None

    def cleanup_expired(self) -> Dict[str, int]:
        """Clean up expired tokens and links."""
        removed = {"tokens": 0, "links": 0}

        # Clean tokens
        expired_tokens = [
            tid for tid, token in self.embed_tokens.items()
            if not token.is_valid()
        ]
        for tid in expired_tokens:
            token = self.embed_tokens.pop(tid, None)
            if token:
                self.token_by_value.pop(token.token, None)
                removed["tokens"] += 1

        # Clean links
        expired_links = [
            lid for lid, link in self.share_links.items()
            if not link.is_valid()
        ]
        for lid in expired_links:
            link = self.share_links.pop(lid, None)
            if link:
                self.link_by_code.pop(link.short_code, None)
                removed["links"] += 1

        return removed

    def get_dashboard_sharing_summary(
        self,
        dashboard_id: str
    ) -> Dict[str, Any]:
        """Get sharing summary for a dashboard."""
        settings = self.get_share_settings(dashboard_id)
        tokens = self.get_embed_tokens(dashboard_id)
        links = self.get_share_links(dashboard_id)

        return {
            "dashboard_id": dashboard_id,
            "share_type": settings.share_type.value,
            "permission_count": len([p for p in settings.permissions if p.is_valid()]),
            "embed_token_count": len([t for t in tokens if t.is_valid()]),
            "share_link_count": len([l for l in links if l.is_valid()]),
            "total_views": settings.current_views,
            "allow_embedding": settings.allow_embedding,
            "password_protected": settings.password_protected,
        }


# =============================================================================
# Embed Renderer
# =============================================================================

@dataclass
class EmbedConfig:
    """Configuration for rendering embedded dashboards."""
    mode: EmbedMode = EmbedMode.FULL
    theme: str = "light"
    show_controls: bool = True
    show_title: bool = True
    show_toolbar: bool = False
    allow_fullscreen: bool = True
    allow_refresh: bool = True
    allow_filters: bool = True
    allow_drill_down: bool = True
    custom_css: str = ""
    width: str = "100%"
    height: str = "600px"
    responsive: bool = True
    loading_text: str = "Loading dashboard..."
    error_text: str = "Failed to load dashboard"


class EmbedRenderer:
    """
    Renders dashboards for embedding.

    Generates HTML/CSS for embedded views.
    """

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def render_embed_html(
        self,
        token: EmbedToken,
        config: Optional[EmbedConfig] = None,
    ) -> str:
        """Render complete HTML for embedded dashboard."""
        config = config or EmbedConfig(
            mode=token.embed_mode,
            show_controls=not token.hide_controls,
            show_title=not token.hide_title,
            theme=token.theme_override or "light",
            custom_css=token.custom_css,
        )

        embed_url = token.get_embed_url(self.base_url)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard Embed</title>
    <style>
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: {self._get_bg_color(config.theme)};
            color: {self._get_text_color(config.theme)};
        }}
        .embed-container {{
            width: {config.width};
            height: {config.height};
            overflow: hidden;
            position: relative;
        }}
        .embed-loading {{
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100%;
            color: #6B7280;
        }}
        .embed-error {{
            display: none;
            align-items: center;
            justify-content: center;
            height: 100%;
            color: #EF4444;
        }}
        .dashboard-frame {{
            width: 100%;
            height: 100%;
            border: none;
        }}
        {config.custom_css}
    </style>
</head>
<body>
    <div class="embed-container">
        <div class="embed-loading" id="loading">{config.loading_text}</div>
        <div class="embed-error" id="error">{config.error_text}</div>
        <iframe
            id="dashboard-frame"
            class="dashboard-frame"
            src="{embed_url}"
            style="display: none;"
            sandbox="allow-scripts allow-same-origin allow-popups"
            allowfullscreen
            loading="lazy"
        ></iframe>
    </div>
    <script>
        const frame = document.getElementById('dashboard-frame');
        const loading = document.getElementById('loading');
        const error = document.getElementById('error');

        frame.onload = function() {{
            loading.style.display = 'none';
            frame.style.display = 'block';
        }};

        frame.onerror = function() {{
            loading.style.display = 'none';
            error.style.display = 'flex';
        }};

        // Handle messages from dashboard
        window.addEventListener('message', function(event) {{
            if (event.origin !== '{self.base_url}') return;

            const data = event.data;
            if (data.type === 'dashboard:ready') {{
                console.log('Dashboard ready');
            }} else if (data.type === 'dashboard:error') {{
                loading.style.display = 'none';
                error.style.display = 'flex';
                error.textContent = data.message || '{config.error_text}';
            }}
        }});
    </script>
</body>
</html>"""

    def render_iframe(
        self,
        token: EmbedToken,
        width: str = "100%",
        height: str = "600px",
        class_name: str = "",
    ) -> str:
        """Render iframe HTML snippet."""
        url = token.get_embed_url(self.base_url)
        classes = f"stance-embed {class_name}".strip()

        return (
            f'<iframe '
            f'src="{url}" '
            f'width="{width}" '
            f'height="{height}" '
            f'class="{classes}" '
            f'frameborder="0" '
            f'allowfullscreen '
            f'sandbox="allow-scripts allow-same-origin allow-popups" '
            f'loading="lazy">'
            f'</iframe>'
        )

    def render_script_embed(
        self,
        token: EmbedToken,
        container_id: str = "stance-dashboard",
    ) -> str:
        """Render JavaScript embed snippet."""
        return f"""
<div id="{container_id}"></div>
<script src="{self.base_url}/embed/sdk.js"></script>
<script>
    StanceEmbed.init({{
        container: '#{container_id}',
        token: '{token.token}',
        mode: '{token.embed_mode.value}',
        theme: '{token.theme_override or "auto"}',
        onReady: function() {{
            console.log('Stance dashboard ready');
        }},
        onError: function(error) {{
            console.error('Stance dashboard error:', error);
        }}
    }});
</script>
"""

    def _get_bg_color(self, theme: str) -> str:
        """Get background color for theme."""
        colors = {
            "light": "#FFFFFF",
            "dark": "#1F2937",
            "auto": "#FFFFFF",
        }
        return colors.get(theme, "#FFFFFF")

    def _get_text_color(self, theme: str) -> str:
        """Get text color for theme."""
        colors = {
            "light": "#1F2937",
            "dark": "#F9FAFB",
            "auto": "#1F2937",
        }
        return colors.get(theme, "#1F2937")


# =============================================================================
# Factory Functions
# =============================================================================

def create_embedding_manager(signing_key: Optional[str] = None) -> EmbeddingManager:
    """Create an embedding manager."""
    return EmbeddingManager(signing_key)


def create_embed_renderer(base_url: str) -> EmbedRenderer:
    """Create an embed renderer."""
    return EmbedRenderer(base_url)


def create_share_settings(dashboard_id: str) -> ShareSettings:
    """Create share settings for a dashboard."""
    return ShareSettings(dashboard_id=dashboard_id)


def create_embed_token(
    dashboard_id: str,
    created_by: str,
    expires_in: Optional[timedelta] = None,
    **kwargs
) -> EmbedToken:
    """Create an embed token."""
    return EmbedToken(
        dashboard_id=dashboard_id,
        created_by=created_by,
        expires_at=datetime.utcnow() + expires_in if expires_in else None,
        **kwargs
    )


def create_share_link(
    dashboard_id: str,
    created_by: str,
    expires_in: Optional[timedelta] = None,
    **kwargs
) -> ShareLink:
    """Create a share link."""
    return ShareLink(
        dashboard_id=dashboard_id,
        created_by=created_by,
        expires_at=datetime.utcnow() + expires_in if expires_in else None,
        **kwargs
    )
