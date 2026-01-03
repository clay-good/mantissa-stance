"""
API key management for Mantissa Stance.

Provides API key generation, validation, and lifecycle management.

Part of Phase 92: API Gateway & Authentication
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from stance.auth.models import (
    APIKey,
    APIKeyScope,
    APIKeyStatus,
)


# =============================================================================
# Exceptions
# =============================================================================

class APIKeyError(Exception):
    """Base API key error."""
    pass


class APIKeyNotFoundError(APIKeyError):
    """API key not found."""
    pass


class APIKeyExpiredError(APIKeyError):
    """API key has expired."""
    pass


class APIKeyRevokedError(APIKeyError):
    """API key has been revoked."""
    pass


class APIKeyRateLimitError(APIKeyError):
    """API key rate limit exceeded."""
    pass


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class APIKeyConfig:
    """
    API key configuration.

    Attributes:
        default_expires_days: Default expiration in days (None = no expiration)
        max_keys_per_user: Maximum keys a user can have
        key_prefix: Prefix for generated keys
        rate_limit_window: Rate limit window in seconds
        default_rate_limit_per_minute: Default rate limit per minute
        default_rate_limit_per_day: Default rate limit per day
        allow_ip_restrictions: Allow IP whitelist restrictions
    """
    default_expires_days: Optional[int] = 365
    max_keys_per_user: int = 10
    key_prefix: str = "stk"
    rate_limit_window: int = 60
    default_rate_limit_per_minute: int = 60
    default_rate_limit_per_day: int = 10000
    allow_ip_restrictions: bool = True


# =============================================================================
# Rate Limiter
# =============================================================================

@dataclass
class RateLimitEntry:
    """Rate limit tracking entry."""
    requests: List[datetime] = field(default_factory=list)
    daily_count: int = 0
    daily_reset: datetime = field(default_factory=lambda: datetime.utcnow().replace(
        hour=0, minute=0, second=0, microsecond=0
    ) + timedelta(days=1))


class RateLimiter:
    """Simple in-memory rate limiter."""

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self._entries: Dict[str, RateLimitEntry] = {}

    def check_rate_limit(
        self,
        key_id: str,
        limit_per_minute: int,
        limit_per_day: int,
    ) -> tuple[bool, Dict[str, Any]]:
        """
        Check if request is within rate limits.

        Returns:
            Tuple of (allowed, info_dict)
        """
        now = datetime.utcnow()

        if key_id not in self._entries:
            self._entries[key_id] = RateLimitEntry()

        entry = self._entries[key_id]

        # Reset daily counter if needed
        if now >= entry.daily_reset:
            entry.daily_count = 0
            entry.daily_reset = now.replace(
                hour=0, minute=0, second=0, microsecond=0
            ) + timedelta(days=1)

        # Clean old requests from window
        window_start = now - timedelta(seconds=self.window_seconds)
        entry.requests = [r for r in entry.requests if r > window_start]

        # Check limits
        minute_count = len(entry.requests)
        daily_count = entry.daily_count

        info = {
            "minute_remaining": max(0, limit_per_minute - minute_count),
            "minute_limit": limit_per_minute,
            "daily_remaining": max(0, limit_per_day - daily_count),
            "daily_limit": limit_per_day,
            "reset_at": entry.daily_reset.isoformat(),
        }

        if minute_count >= limit_per_minute:
            info["retry_after"] = self.window_seconds
            return False, info

        if daily_count >= limit_per_day:
            info["retry_after"] = int((entry.daily_reset - now).total_seconds())
            return False, info

        return True, info

    def record_request(self, key_id: str) -> None:
        """Record a request for rate limiting."""
        now = datetime.utcnow()

        if key_id not in self._entries:
            self._entries[key_id] = RateLimitEntry()

        entry = self._entries[key_id]
        entry.requests.append(now)
        entry.daily_count += 1


# =============================================================================
# API Key Manager
# =============================================================================

class APIKeyManager:
    """
    API key manager.

    Handles API key lifecycle, validation, and rate limiting.
    """

    def __init__(self, config: Optional[APIKeyConfig] = None):
        """
        Initialize API key manager.

        Args:
            config: API key configuration
        """
        self.config = config or APIKeyConfig()
        self._keys: Dict[str, APIKey] = {}
        self._key_hash_index: Dict[str, str] = {}  # hash -> key_id
        self._user_keys: Dict[str, List[str]] = {}  # user_id -> [key_ids]
        self._rate_limiter = RateLimiter(self.config.rate_limit_window)

    def create_key(
        self,
        name: str,
        user_id: str,
        tenant_id: Optional[str] = None,
        description: str = "",
        expires_in_days: Optional[int] = None,
        scope: Optional[APIKeyScope] = None,
    ) -> tuple[APIKey, str]:
        """
        Create a new API key.

        Args:
            name: Key name
            user_id: Owner user ID
            tenant_id: Optional tenant ID
            description: Key description
            expires_in_days: Days until expiration (None = use default)
            scope: Optional scope restrictions

        Returns:
            Tuple of (APIKey, plaintext_key)
            The plaintext key is only available at creation time.

        Raises:
            APIKeyError: If user has too many keys
        """
        # Check key limit
        user_key_count = len(self._user_keys.get(user_id, []))
        if user_key_count >= self.config.max_keys_per_user:
            raise APIKeyError(
                f"User has reached maximum of {self.config.max_keys_per_user} API keys"
            )

        # Use default expiration if not specified
        if expires_in_days is None:
            expires_in_days = self.config.default_expires_days

        # Create scope with defaults if not provided
        if scope is None:
            scope = APIKeyScope(
                rate_limit_per_minute=self.config.default_rate_limit_per_minute,
                rate_limit_per_day=self.config.default_rate_limit_per_day,
            )

        # Generate the key
        api_key, plaintext = APIKey.generate(
            name=name,
            user_id=user_id,
            tenant_id=tenant_id,
            scope=scope,
            expires_in_days=expires_in_days,
        )
        api_key.description = description

        # Store the key
        self._keys[api_key.id] = api_key
        self._key_hash_index[api_key.key_hash] = api_key.id

        # Track user's keys
        if user_id not in self._user_keys:
            self._user_keys[user_id] = []
        self._user_keys[user_id].append(api_key.id)

        return api_key, plaintext

    def validate_key(
        self,
        plaintext_key: str,
        ip_address: Optional[str] = None,
        check_rate_limit: bool = True,
    ) -> APIKey:
        """
        Validate an API key.

        Args:
            plaintext_key: The API key to validate
            ip_address: Client IP address for IP restriction check
            check_rate_limit: Whether to check rate limits

        Returns:
            The validated APIKey

        Raises:
            APIKeyNotFoundError: If key not found
            APIKeyExpiredError: If key has expired
            APIKeyRevokedError: If key has been revoked
            APIKeyRateLimitError: If rate limit exceeded
        """
        # Hash the key to look it up
        key_hash = APIKey.hash_key(plaintext_key)

        if key_hash not in self._key_hash_index:
            raise APIKeyNotFoundError("API key not found")

        key_id = self._key_hash_index[key_hash]
        api_key = self._keys.get(key_id)

        if api_key is None:
            raise APIKeyNotFoundError("API key not found")

        # Check status
        if api_key.status == APIKeyStatus.REVOKED:
            raise APIKeyRevokedError("API key has been revoked")

        if api_key.status == APIKeyStatus.DISABLED:
            raise APIKeyRevokedError("API key is disabled")

        # Check expiration
        if api_key.is_expired():
            api_key.status = APIKeyStatus.EXPIRED
            raise APIKeyExpiredError("API key has expired")

        # Check IP restriction
        if ip_address and not api_key.scope.allows_ip(ip_address):
            raise APIKeyError(f"IP address {ip_address} not allowed")

        # Check rate limit
        if check_rate_limit:
            allowed, info = self._rate_limiter.check_rate_limit(
                api_key.id,
                api_key.scope.rate_limit_per_minute,
                api_key.scope.rate_limit_per_day,
            )
            if not allowed:
                raise APIKeyRateLimitError(
                    f"Rate limit exceeded. Retry after {info.get('retry_after', 60)} seconds"
                )

        return api_key

    def use_key(self, api_key: APIKey) -> None:
        """
        Record API key usage.

        Args:
            api_key: The key being used
        """
        api_key.record_use()
        self._rate_limiter.record_request(api_key.id)

    def get_key(self, key_id: str) -> Optional[APIKey]:
        """Get an API key by ID."""
        return self._keys.get(key_id)

    def get_key_by_prefix(self, prefix: str) -> Optional[APIKey]:
        """Get an API key by its prefix."""
        for key in self._keys.values():
            if key.key_prefix == prefix:
                return key
        return None

    def list_user_keys(self, user_id: str) -> List[APIKey]:
        """List all API keys for a user."""
        key_ids = self._user_keys.get(user_id, [])
        return [self._keys[kid] for kid in key_ids if kid in self._keys]

    def list_tenant_keys(self, tenant_id: str) -> List[APIKey]:
        """List all API keys for a tenant."""
        return [k for k in self._keys.values() if k.tenant_id == tenant_id]

    def revoke_key(
        self,
        key_id: str,
        revoked_by: str,
        reason: str = "",
    ) -> APIKey:
        """
        Revoke an API key.

        Args:
            key_id: Key ID to revoke
            revoked_by: User ID revoking the key
            reason: Reason for revocation

        Returns:
            The revoked APIKey

        Raises:
            APIKeyNotFoundError: If key not found
        """
        api_key = self._keys.get(key_id)
        if api_key is None:
            raise APIKeyNotFoundError(f"API key not found: {key_id}")

        api_key.revoke(revoked_by, reason)
        return api_key

    def revoke_all_user_keys(
        self,
        user_id: str,
        revoked_by: str,
        reason: str = "",
    ) -> int:
        """
        Revoke all API keys for a user.

        Returns:
            Number of keys revoked
        """
        count = 0
        for key in self.list_user_keys(user_id):
            if key.status == APIKeyStatus.ACTIVE:
                key.revoke(revoked_by, reason)
                count += 1
        return count

    def delete_key(self, key_id: str) -> bool:
        """
        Delete an API key permanently.

        Args:
            key_id: Key ID to delete

        Returns:
            True if deleted, False if not found
        """
        api_key = self._keys.get(key_id)
        if api_key is None:
            return False

        # Remove from all indexes
        del self._keys[key_id]
        if api_key.key_hash in self._key_hash_index:
            del self._key_hash_index[api_key.key_hash]
        if api_key.user_id in self._user_keys:
            self._user_keys[api_key.user_id] = [
                k for k in self._user_keys[api_key.user_id] if k != key_id
            ]

        return True

    def cleanup_expired_keys(self, delete: bool = False) -> int:
        """
        Clean up expired keys.

        Args:
            delete: If True, delete expired keys. If False, just mark as expired.

        Returns:
            Number of keys cleaned up
        """
        now = datetime.utcnow()
        count = 0

        for key in list(self._keys.values()):
            if key.expires_at and now >= key.expires_at:
                if key.status == APIKeyStatus.ACTIVE:
                    key.status = APIKeyStatus.EXPIRED
                    count += 1
                if delete:
                    self.delete_key(key.id)

        return count

    def rotate_key(
        self,
        key_id: str,
        user_id: str,
        expires_in_days: Optional[int] = None,
    ) -> tuple[APIKey, str]:
        """
        Rotate an API key (create new, revoke old).

        Args:
            key_id: Key ID to rotate
            user_id: User ID (for authorization)
            expires_in_days: Days until new key expires

        Returns:
            Tuple of (new APIKey, new plaintext_key)

        Raises:
            APIKeyNotFoundError: If key not found
            APIKeyError: If key doesn't belong to user
        """
        old_key = self._keys.get(key_id)
        if old_key is None:
            raise APIKeyNotFoundError(f"API key not found: {key_id}")

        if old_key.user_id != user_id:
            raise APIKeyError("API key does not belong to user")

        # Create new key with same settings
        new_key, plaintext = self.create_key(
            name=old_key.name,
            user_id=old_key.user_id,
            tenant_id=old_key.tenant_id,
            description=f"Rotated from {old_key.key_prefix}",
            expires_in_days=expires_in_days,
            scope=old_key.scope,
        )

        # Revoke old key
        old_key.revoke(user_id, f"Rotated to {new_key.key_prefix}")

        return new_key, plaintext

    def get_rate_limit_info(self, key_id: str) -> Dict[str, Any]:
        """Get rate limit information for a key."""
        api_key = self._keys.get(key_id)
        if api_key is None:
            return {}

        _, info = self._rate_limiter.check_rate_limit(
            key_id,
            api_key.scope.rate_limit_per_minute,
            api_key.scope.rate_limit_per_day,
        )
        return info

    def get_stats(self) -> Dict[str, Any]:
        """Get API key manager statistics."""
        active = sum(1 for k in self._keys.values() if k.status == APIKeyStatus.ACTIVE)
        expired = sum(1 for k in self._keys.values() if k.status == APIKeyStatus.EXPIRED)
        revoked = sum(1 for k in self._keys.values() if k.status == APIKeyStatus.REVOKED)

        return {
            "total_keys": len(self._keys),
            "active_keys": active,
            "expired_keys": expired,
            "revoked_keys": revoked,
            "total_users_with_keys": len(self._user_keys),
            "max_keys_per_user": self.config.max_keys_per_user,
        }


def create_api_key_manager(
    max_keys_per_user: int = 10,
    default_expires_days: Optional[int] = 365,
    rate_limit_per_minute: int = 60,
    rate_limit_per_day: int = 10000,
) -> APIKeyManager:
    """
    Factory function to create an API key manager.

    Args:
        max_keys_per_user: Maximum keys per user
        default_expires_days: Default key expiration
        rate_limit_per_minute: Default rate limit per minute
        rate_limit_per_day: Default rate limit per day

    Returns:
        Configured APIKeyManager
    """
    config = APIKeyConfig(
        max_keys_per_user=max_keys_per_user,
        default_expires_days=default_expires_days,
        default_rate_limit_per_minute=rate_limit_per_minute,
        default_rate_limit_per_day=rate_limit_per_day,
    )
    return APIKeyManager(config)
