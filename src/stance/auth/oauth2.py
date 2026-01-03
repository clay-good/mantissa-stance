"""
OAuth2/OIDC provider integration for Mantissa Stance.

Provides OAuth2 and OpenID Connect authentication capabilities.

Part of Phase 92: API Gateway & Authentication
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


# =============================================================================
# Exceptions
# =============================================================================

class OAuth2Error(Exception):
    """Base OAuth2 error."""
    pass


class OAuth2TokenError(OAuth2Error):
    """Token exchange or validation error."""
    pass


class OAuth2ConfigError(OAuth2Error):
    """Configuration error."""
    pass


# =============================================================================
# Configuration
# =============================================================================

class OAuth2GrantType(Enum):
    """OAuth2 grant types."""
    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    REFRESH_TOKEN = "refresh_token"
    PASSWORD = "password"  # Not recommended


class OAuth2ResponseType(Enum):
    """OAuth2 response types."""
    CODE = "code"
    TOKEN = "token"
    ID_TOKEN = "id_token"


@dataclass
class OAuth2Config:
    """
    OAuth2 provider configuration.

    Attributes:
        provider_name: Name of the OAuth2 provider
        client_id: OAuth2 client ID
        client_secret: OAuth2 client secret
        authorization_endpoint: Authorization URL
        token_endpoint: Token exchange URL
        userinfo_endpoint: User info URL (optional)
        revocation_endpoint: Token revocation URL (optional)
        scopes: Default scopes to request
        redirect_uri: Callback URI
        response_type: OAuth2 response type
        grant_types: Supported grant types
        pkce_required: Require PKCE for authorization code flow
        state_timeout: State parameter timeout in seconds
    """
    provider_name: str
    client_id: str
    client_secret: str = ""
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    userinfo_endpoint: str = ""
    revocation_endpoint: str = ""
    scopes: List[str] = field(default_factory=lambda: ["openid", "profile", "email"])
    redirect_uri: str = ""
    response_type: OAuth2ResponseType = OAuth2ResponseType.CODE
    grant_types: List[OAuth2GrantType] = field(
        default_factory=lambda: [OAuth2GrantType.AUTHORIZATION_CODE]
    )
    pkce_required: bool = True
    state_timeout: int = 600  # 10 minutes


@dataclass
class OIDCConfig(OAuth2Config):
    """
    OpenID Connect provider configuration.

    Extends OAuth2Config with OIDC-specific settings.
    """
    issuer: str = ""
    jwks_uri: str = ""
    end_session_endpoint: str = ""
    claims_supported: List[str] = field(default_factory=list)
    id_token_signing_alg: str = "RS256"
    require_nonce: bool = True

    @classmethod
    def from_discovery(cls, issuer: str, client_id: str, client_secret: str = "") -> "OIDCConfig":
        """
        Create config from OIDC discovery document.

        Note: In a real implementation, this would fetch the discovery document.
        """
        # This is a placeholder - real implementation would fetch from issuer/.well-known/openid-configuration
        return cls(
            provider_name="oidc",
            client_id=client_id,
            client_secret=client_secret,
            issuer=issuer,
            authorization_endpoint=f"{issuer}/authorize",
            token_endpoint=f"{issuer}/token",
            userinfo_endpoint=f"{issuer}/userinfo",
            jwks_uri=f"{issuer}/.well-known/jwks.json",
            end_session_endpoint=f"{issuer}/logout",
        )


# =============================================================================
# OAuth2 State Management
# =============================================================================

@dataclass
class OAuth2State:
    """OAuth2 authorization state."""
    state: str
    code_verifier: Optional[str] = None  # For PKCE
    nonce: Optional[str] = None  # For OIDC
    redirect_uri: str = ""
    scopes: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime = field(default_factory=lambda: datetime.utcnow() + timedelta(minutes=10))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if state has expired."""
        return datetime.utcnow() >= self.expires_at


@dataclass
class OAuth2Token:
    """OAuth2 token response."""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    refresh_token: Optional[str] = None
    scope: str = ""
    id_token: Optional[str] = None
    received_at: datetime = field(default_factory=datetime.utcnow)

    def is_expired(self) -> bool:
        """Check if access token is expired."""
        expires_at = self.received_at + timedelta(seconds=self.expires_in)
        return datetime.utcnow() >= expires_at

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "scope": self.scope,
        }
        if self.refresh_token:
            result["refresh_token"] = self.refresh_token
        if self.id_token:
            result["id_token"] = self.id_token
        return result


@dataclass
class OIDCUserInfo:
    """OIDC user info claims."""
    sub: str  # Subject (unique user ID)
    email: Optional[str] = None
    email_verified: bool = False
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    preferred_username: Optional[str] = None
    picture: Optional[str] = None
    locale: Optional[str] = None
    zoneinfo: Optional[str] = None
    updated_at: Optional[int] = None
    groups: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    custom_claims: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_claims(cls, claims: Dict[str, Any]) -> "OIDCUserInfo":
        """Create from claims dictionary."""
        return cls(
            sub=claims.get("sub", ""),
            email=claims.get("email"),
            email_verified=claims.get("email_verified", False),
            name=claims.get("name"),
            given_name=claims.get("given_name"),
            family_name=claims.get("family_name"),
            preferred_username=claims.get("preferred_username"),
            picture=claims.get("picture"),
            locale=claims.get("locale"),
            zoneinfo=claims.get("zoneinfo"),
            updated_at=claims.get("updated_at"),
            groups=claims.get("groups", []),
            roles=claims.get("roles", []),
        )


# =============================================================================
# OAuth2 Provider
# =============================================================================

class OAuth2Provider:
    """
    OAuth2 provider integration.

    Handles OAuth2 authorization flow and token management.
    """

    def __init__(self, config: OAuth2Config):
        """
        Initialize OAuth2 provider.

        Args:
            config: OAuth2 configuration
        """
        self.config = config
        self._states: Dict[str, OAuth2State] = {}

    def generate_authorization_url(
        self,
        redirect_uri: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        state_metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, OAuth2State]:
        """
        Generate authorization URL for OAuth2 flow.

        Args:
            redirect_uri: Override redirect URI
            scopes: Override scopes
            state_metadata: Additional metadata to store with state

        Returns:
            Tuple of (authorization_url, state_object)
        """
        # Generate state
        state_value = secrets.token_urlsafe(32)
        code_verifier = None
        code_challenge = None

        # Generate PKCE parameters if required
        if self.config.pkce_required:
            code_verifier = secrets.token_urlsafe(64)
            code_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).rstrip(b"=").decode()

        # Create state object
        state = OAuth2State(
            state=state_value,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri or self.config.redirect_uri,
            scopes=scopes or self.config.scopes,
            metadata=state_metadata or {},
            expires_at=datetime.utcnow() + timedelta(seconds=self.config.state_timeout),
        )
        self._states[state_value] = state

        # Build authorization URL
        params = {
            "response_type": self.config.response_type.value,
            "client_id": self.config.client_id,
            "redirect_uri": state.redirect_uri,
            "scope": " ".join(state.scopes),
            "state": state_value,
        }

        if self.config.pkce_required and code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"

        url = f"{self.config.authorization_endpoint}?{urllib.parse.urlencode(params)}"
        return url, state

    def validate_callback(
        self,
        state: str,
        code: Optional[str] = None,
        error: Optional[str] = None,
        error_description: Optional[str] = None,
    ) -> OAuth2State:
        """
        Validate OAuth2 callback parameters.

        Args:
            state: State parameter from callback
            code: Authorization code (for code flow)
            error: Error parameter
            error_description: Error description

        Returns:
            The validated state object

        Raises:
            OAuth2Error: If validation fails
        """
        if error:
            raise OAuth2Error(f"OAuth2 error: {error} - {error_description}")

        if state not in self._states:
            raise OAuth2Error("Invalid or expired state parameter")

        stored_state = self._states[state]

        if stored_state.is_expired():
            del self._states[state]
            raise OAuth2Error("State parameter has expired")

        if self.config.response_type == OAuth2ResponseType.CODE and not code:
            raise OAuth2Error("Missing authorization code")

        return stored_state

    def exchange_code(
        self,
        code: str,
        state: OAuth2State,
    ) -> OAuth2Token:
        """
        Exchange authorization code for tokens.

        Note: In a real implementation, this would make an HTTP request.
        This is a placeholder that simulates the exchange.

        Args:
            code: Authorization code
            state: State object from authorization

        Returns:
            OAuth2Token with access and refresh tokens
        """
        # Clean up used state
        if state.state in self._states:
            del self._states[state.state]

        # In a real implementation, this would POST to token_endpoint
        # For now, return a simulated token
        return OAuth2Token(
            access_token=f"simulated_access_token_{secrets.token_hex(16)}",
            token_type="Bearer",
            expires_in=3600,
            refresh_token=f"simulated_refresh_token_{secrets.token_hex(16)}",
            scope=" ".join(state.scopes),
        )

    def refresh_token(self, refresh_token: str) -> OAuth2Token:
        """
        Refresh an access token.

        Note: Placeholder implementation.

        Args:
            refresh_token: Refresh token

        Returns:
            New OAuth2Token
        """
        return OAuth2Token(
            access_token=f"refreshed_access_token_{secrets.token_hex(16)}",
            token_type="Bearer",
            expires_in=3600,
            refresh_token=f"new_refresh_token_{secrets.token_hex(16)}",
        )

    def revoke_token(self, token: str) -> bool:
        """
        Revoke a token.

        Note: Placeholder implementation.

        Args:
            token: Token to revoke

        Returns:
            True if revoked successfully
        """
        # In a real implementation, this would POST to revocation_endpoint
        return True

    def cleanup_expired_states(self) -> int:
        """Clean up expired state parameters."""
        now = datetime.utcnow()
        expired = [s for s, state in self._states.items() if state.is_expired()]
        for s in expired:
            del self._states[s]
        return len(expired)

    def get_stats(self) -> Dict[str, Any]:
        """Get provider statistics."""
        return {
            "provider_name": self.config.provider_name,
            "pending_states": len(self._states),
            "pkce_required": self.config.pkce_required,
            "scopes": self.config.scopes,
        }


# =============================================================================
# OIDC Provider
# =============================================================================

class OIDCProvider(OAuth2Provider):
    """
    OpenID Connect provider integration.

    Extends OAuth2Provider with OIDC-specific functionality.
    """

    def __init__(self, config: OIDCConfig):
        """
        Initialize OIDC provider.

        Args:
            config: OIDC configuration
        """
        super().__init__(config)
        self.oidc_config = config

    def generate_authorization_url(
        self,
        redirect_uri: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        state_metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, OAuth2State]:
        """Generate OIDC authorization URL with nonce."""
        url, state = super().generate_authorization_url(
            redirect_uri=redirect_uri,
            scopes=scopes,
            state_metadata=state_metadata,
        )

        # Add nonce for OIDC
        if self.oidc_config.require_nonce:
            nonce = secrets.token_urlsafe(32)
            state.nonce = nonce
            url += f"&nonce={nonce}"

        return url, state

    def exchange_code(
        self,
        code: str,
        state: OAuth2State,
    ) -> OAuth2Token:
        """Exchange code and return tokens including ID token."""
        token = super().exchange_code(code, state)

        # Simulate ID token (in real implementation, this comes from the provider)
        token.id_token = f"simulated_id_token_{secrets.token_hex(32)}"

        return token

    def validate_id_token(self, id_token: str, nonce: Optional[str] = None) -> Dict[str, Any]:
        """
        Validate an ID token.

        Note: Placeholder implementation. Real implementation would:
        1. Decode the JWT
        2. Verify signature using JWKS
        3. Validate claims (iss, aud, exp, nonce)

        Args:
            id_token: The ID token to validate
            nonce: Expected nonce value

        Returns:
            Validated claims
        """
        # Placeholder - return simulated claims
        return {
            "sub": f"user_{secrets.token_hex(8)}",
            "email": "user@example.com",
            "email_verified": True,
            "name": "Example User",
            "nonce": nonce,
        }

    def get_userinfo(self, access_token: str) -> OIDCUserInfo:
        """
        Fetch user info from the userinfo endpoint.

        Note: Placeholder implementation.

        Args:
            access_token: Access token

        Returns:
            OIDCUserInfo with user claims
        """
        # Placeholder - return simulated user info
        return OIDCUserInfo(
            sub=f"user_{secrets.token_hex(8)}",
            email="user@example.com",
            email_verified=True,
            name="Example User",
            given_name="Example",
            family_name="User",
            preferred_username="exampleuser",
        )

    def generate_logout_url(
        self,
        id_token_hint: Optional[str] = None,
        post_logout_redirect_uri: Optional[str] = None,
    ) -> str:
        """
        Generate OIDC logout URL.

        Args:
            id_token_hint: ID token to hint user identity
            post_logout_redirect_uri: Where to redirect after logout

        Returns:
            Logout URL
        """
        params = {}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri

        if params:
            return f"{self.oidc_config.end_session_endpoint}?{urllib.parse.urlencode(params)}"
        return self.oidc_config.end_session_endpoint


# =============================================================================
# Factory Functions
# =============================================================================

def create_oauth2_provider(
    provider_name: str,
    client_id: str,
    client_secret: str,
    authorization_endpoint: str,
    token_endpoint: str,
    redirect_uri: str,
    scopes: Optional[List[str]] = None,
) -> OAuth2Provider:
    """Create an OAuth2 provider."""
    config = OAuth2Config(
        provider_name=provider_name,
        client_id=client_id,
        client_secret=client_secret,
        authorization_endpoint=authorization_endpoint,
        token_endpoint=token_endpoint,
        redirect_uri=redirect_uri,
        scopes=scopes or ["openid", "profile", "email"],
    )
    return OAuth2Provider(config)


def create_oidc_provider(
    provider_name: str,
    client_id: str,
    client_secret: str,
    issuer: str,
    redirect_uri: str,
    scopes: Optional[List[str]] = None,
) -> OIDCProvider:
    """Create an OIDC provider from issuer URL."""
    config = OIDCConfig(
        provider_name=provider_name,
        client_id=client_id,
        client_secret=client_secret,
        issuer=issuer,
        authorization_endpoint=f"{issuer}/authorize",
        token_endpoint=f"{issuer}/token",
        userinfo_endpoint=f"{issuer}/userinfo",
        jwks_uri=f"{issuer}/.well-known/jwks.json",
        end_session_endpoint=f"{issuer}/logout",
        redirect_uri=redirect_uri,
        scopes=scopes or ["openid", "profile", "email"],
    )
    return OIDCProvider(config)
