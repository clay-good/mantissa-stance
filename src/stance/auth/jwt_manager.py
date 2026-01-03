"""
JWT token management for Mantissa Stance.

Provides JWT token generation, validation, and refresh capabilities.

Part of Phase 92: API Gateway & Authentication
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from stance.auth.models import (
    TokenPayload,
    TokenPair,
    TokenType,
    RefreshToken,
    User,
)


# =============================================================================
# Exceptions
# =============================================================================

class JWTError(Exception):
    """Base JWT error."""
    pass


class TokenExpiredError(JWTError):
    """Token has expired."""
    pass


class InvalidTokenError(JWTError):
    """Token is invalid."""
    pass


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class JWTConfig:
    """
    JWT configuration.

    Attributes:
        secret_key: Secret key for HMAC signing
        algorithm: Signing algorithm (HS256, HS384, HS512)
        issuer: Token issuer claim
        audience: Token audience claim
        access_token_expires: Access token expiration in seconds
        refresh_token_expires: Refresh token expiration in seconds
        leeway: Clock skew tolerance in seconds
        require_exp: Require expiration claim
        require_iat: Require issued-at claim
    """
    secret_key: str = ""
    algorithm: str = "HS256"
    issuer: str = "mantissa-stance"
    audience: str = "mantissa-stance-api"
    access_token_expires: int = 3600  # 1 hour
    refresh_token_expires: int = 604800  # 7 days
    leeway: int = 60  # 1 minute
    require_exp: bool = True
    require_iat: bool = True
    include_user_info: bool = True
    include_permissions: bool = True

    def __post_init__(self):
        if not self.secret_key:
            # Generate a random secret if not provided
            self.secret_key = secrets.token_hex(32)


# =============================================================================
# JWT Manager
# =============================================================================

class JWTManager:
    """
    JWT token manager.

    Handles token generation, validation, and refresh.
    """

    def __init__(self, config: Optional[JWTConfig] = None):
        """
        Initialize JWT manager.

        Args:
            config: JWT configuration
        """
        self.config = config or JWTConfig()
        self._refresh_tokens: Dict[str, RefreshToken] = {}
        self._revoked_tokens: set = set()

    def generate_tokens(
        self,
        user: User,
        session_id: Optional[str] = None,
        custom_claims: Optional[Dict[str, Any]] = None,
    ) -> TokenPair:
        """
        Generate access and refresh token pair.

        Args:
            user: User to generate tokens for
            session_id: Optional session ID to include
            custom_claims: Optional custom claims

        Returns:
            TokenPair with access and refresh tokens
        """
        now = datetime.utcnow()

        # Build access token payload
        access_payload = TokenPayload(
            sub=user.id,
            type=TokenType.ACCESS,
            iss=self.config.issuer,
            aud=self.config.audience,
            iat=now,
            exp=now + timedelta(seconds=self.config.access_token_expires),
            email=user.email if self.config.include_user_info else "",
            username=user.username if self.config.include_user_info else "",
            roles=[r.value for r in user.roles] if self.config.include_permissions else [],
            permissions=list(user.permissions) if self.config.include_permissions else [],
            tenant_id=user.tenant_id,
            session_id=session_id,
            custom_claims=custom_claims or {},
        )

        # Build refresh token payload
        refresh_payload = TokenPayload(
            sub=user.id,
            type=TokenType.REFRESH,
            iss=self.config.issuer,
            aud=self.config.audience,
            iat=now,
            exp=now + timedelta(seconds=self.config.refresh_token_expires),
            session_id=session_id,
        )

        # Encode tokens
        access_token = self._encode_token(access_payload)
        refresh_token = self._encode_token(refresh_payload)

        # Store refresh token for revocation tracking
        refresh_record = RefreshToken(
            id=refresh_payload.jti,
            token_hash=hashlib.sha256(refresh_token.encode()).hexdigest(),
            user_id=user.id,
            session_id=session_id,
            expires_at=refresh_payload.exp,
        )
        self._refresh_tokens[refresh_record.id] = refresh_record

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self.config.access_token_expires,
            refresh_expires_in=self.config.refresh_token_expires,
        )

    def validate_token(self, token: str) -> TokenPayload:
        """
        Validate a JWT token.

        Args:
            token: JWT token string

        Returns:
            TokenPayload with validated claims

        Raises:
            InvalidTokenError: If token is invalid
            TokenExpiredError: If token has expired
        """
        try:
            payload = self._decode_token(token)
        except Exception as e:
            raise InvalidTokenError(f"Failed to decode token: {e}")

        # Check if token is revoked
        if payload.jti in self._revoked_tokens:
            raise InvalidTokenError("Token has been revoked")

        # Check expiration
        if payload.exp:
            if datetime.utcnow() > payload.exp + timedelta(seconds=self.config.leeway):
                raise TokenExpiredError("Token has expired")

        # Check not-before
        if payload.nbf:
            if datetime.utcnow() < payload.nbf - timedelta(seconds=self.config.leeway):
                raise InvalidTokenError("Token is not yet valid")

        # Validate issuer
        if payload.iss != self.config.issuer:
            raise InvalidTokenError(f"Invalid issuer: {payload.iss}")

        # Validate audience
        if payload.aud != self.config.audience:
            raise InvalidTokenError(f"Invalid audience: {payload.aud}")

        return payload

    def refresh_tokens(
        self,
        refresh_token: str,
        user: User,
    ) -> TokenPair:
        """
        Refresh tokens using a refresh token.

        Args:
            refresh_token: Current refresh token
            user: User to refresh tokens for

        Returns:
            New TokenPair

        Raises:
            InvalidTokenError: If refresh token is invalid
        """
        # Validate the refresh token
        payload = self.validate_token(refresh_token)

        if payload.type != TokenType.REFRESH:
            raise InvalidTokenError("Not a refresh token")

        if payload.sub != user.id:
            raise InvalidTokenError("Token does not belong to user")

        # Check if refresh token is in our store
        if payload.jti in self._refresh_tokens:
            stored = self._refresh_tokens[payload.jti]
            if not stored.is_valid():
                raise InvalidTokenError("Refresh token has been revoked")

            # Revoke old refresh token (rotation)
            stored.revoke()

        # Generate new tokens
        new_tokens = self.generate_tokens(user, session_id=payload.session_id)

        # Update old refresh token with replacement
        if payload.jti in self._refresh_tokens:
            self._refresh_tokens[payload.jti].replaced_by = new_tokens.refresh_token[:16]

        return new_tokens

    def revoke_token(self, token: str) -> None:
        """
        Revoke a token.

        Args:
            token: Token to revoke
        """
        try:
            payload = self._decode_token(token)
            self._revoked_tokens.add(payload.jti)

            # If it's a refresh token, also revoke in store
            if payload.jti in self._refresh_tokens:
                self._refresh_tokens[payload.jti].revoke()
        except Exception:
            pass  # Invalid token, nothing to revoke

    def revoke_all_user_tokens(self, user_id: str) -> int:
        """
        Revoke all tokens for a user.

        Args:
            user_id: User ID to revoke tokens for

        Returns:
            Number of tokens revoked
        """
        count = 0
        for token_id, token in self._refresh_tokens.items():
            if token.user_id == user_id and not token.is_revoked:
                token.revoke()
                self._revoked_tokens.add(token_id)
                count += 1
        return count

    def revoke_session_tokens(self, session_id: str) -> int:
        """
        Revoke all tokens for a session.

        Args:
            session_id: Session ID to revoke tokens for

        Returns:
            Number of tokens revoked
        """
        count = 0
        for token_id, token in self._refresh_tokens.items():
            if token.session_id == session_id and not token.is_revoked:
                token.revoke()
                self._revoked_tokens.add(token_id)
                count += 1
        return count

    def cleanup_expired_tokens(self) -> int:
        """
        Clean up expired tokens from storage.

        Returns:
            Number of tokens cleaned up
        """
        now = datetime.utcnow()
        expired = [
            token_id for token_id, token in self._refresh_tokens.items()
            if now >= token.expires_at
        ]
        for token_id in expired:
            del self._refresh_tokens[token_id]
            self._revoked_tokens.discard(token_id)
        return len(expired)

    def _encode_token(self, payload: TokenPayload) -> str:
        """
        Encode a token payload to JWT string.

        Uses pure Python implementation for HMAC-SHA256.
        """
        # Header
        header = {
            "alg": self.config.algorithm,
            "typ": "JWT",
        }

        # Encode header and payload
        header_b64 = self._base64url_encode(json.dumps(header))
        payload_b64 = self._base64url_encode(json.dumps(payload.to_dict()))

        # Create signature
        message = f"{header_b64}.{payload_b64}"
        signature = self._sign(message)
        signature_b64 = self._base64url_encode_bytes(signature)

        return f"{header_b64}.{payload_b64}.{signature_b64}"

    def _decode_token(self, token: str) -> TokenPayload:
        """
        Decode a JWT string to token payload.
        """
        parts = token.split(".")
        if len(parts) != 3:
            raise InvalidTokenError("Invalid token format")

        header_b64, payload_b64, signature_b64 = parts

        # Verify signature
        message = f"{header_b64}.{payload_b64}"
        expected_signature = self._sign(message)
        actual_signature = self._base64url_decode_bytes(signature_b64)

        if not hmac.compare_digest(expected_signature, actual_signature):
            raise InvalidTokenError("Invalid signature")

        # Decode payload
        try:
            payload_json = self._base64url_decode(payload_b64)
            claims = json.loads(payload_json)
        except Exception as e:
            raise InvalidTokenError(f"Failed to decode payload: {e}")

        return TokenPayload.from_dict(claims)

    def _sign(self, message: str) -> bytes:
        """Create HMAC signature."""
        if self.config.algorithm == "HS256":
            return hmac.new(
                self.config.secret_key.encode(),
                message.encode(),
                hashlib.sha256,
            ).digest()
        elif self.config.algorithm == "HS384":
            return hmac.new(
                self.config.secret_key.encode(),
                message.encode(),
                hashlib.sha384,
            ).digest()
        elif self.config.algorithm == "HS512":
            return hmac.new(
                self.config.secret_key.encode(),
                message.encode(),
                hashlib.sha512,
            ).digest()
        else:
            raise JWTError(f"Unsupported algorithm: {self.config.algorithm}")

    @staticmethod
    def _base64url_encode(data: str) -> str:
        """Base64url encode a string."""
        return base64.urlsafe_b64encode(data.encode()).rstrip(b"=").decode()

    @staticmethod
    def _base64url_encode_bytes(data: bytes) -> str:
        """Base64url encode bytes."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    @staticmethod
    def _base64url_decode(data: str) -> str:
        """Base64url decode to string."""
        # Add padding
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data).decode()

    @staticmethod
    def _base64url_decode_bytes(data: str) -> bytes:
        """Base64url decode to bytes."""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)

    def get_stats(self) -> Dict[str, Any]:
        """Get JWT manager statistics."""
        active_refresh = sum(
            1 for t in self._refresh_tokens.values()
            if t.is_valid()
        )
        return {
            "total_refresh_tokens": len(self._refresh_tokens),
            "active_refresh_tokens": active_refresh,
            "revoked_tokens": len(self._revoked_tokens),
            "algorithm": self.config.algorithm,
            "access_token_expires_seconds": self.config.access_token_expires,
            "refresh_token_expires_seconds": self.config.refresh_token_expires,
        }


def create_jwt_manager(
    secret_key: Optional[str] = None,
    algorithm: str = "HS256",
    access_expires: int = 3600,
    refresh_expires: int = 604800,
) -> JWTManager:
    """
    Factory function to create a JWT manager.

    Args:
        secret_key: Secret key for signing (generates random if not provided)
        algorithm: Signing algorithm
        access_expires: Access token expiration in seconds
        refresh_expires: Refresh token expiration in seconds

    Returns:
        Configured JWTManager
    """
    config = JWTConfig(
        secret_key=secret_key or secrets.token_hex(32),
        algorithm=algorithm,
        access_token_expires=access_expires,
        refresh_token_expires=refresh_expires,
    )
    return JWTManager(config)
