"""
OAuth2/OIDC provider integration for Mantissa Stance.

Provides OAuth2 and OpenID Connect authentication capabilities.

Part of Phase 92: API Gateway & Authentication
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import socket
import threading
import urllib.parse
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    httpx = None  # type: ignore
    HTTPX_AVAILABLE = False


def _is_production_environment() -> bool:
    """Check if running in a production environment."""
    return any([
        os.environ.get("STANCE_ENV", "").lower() == "production",
        os.environ.get("STANCE_PRODUCTION", "").lower() in ("1", "true", "yes"),
        os.environ.get("ENV", "").lower() == "production",
        os.environ.get("ENVIRONMENT", "").lower() == "production",
        os.environ.get("NODE_ENV", "").lower() == "production",
    ])


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/internal."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
            # AWS/Cloud metadata endpoints
            or ip_str.startswith("169.254.")
        )
    except ValueError:
        return False


def _validate_oauth_url(url: str, context: str = "OAuth") -> None:
    """
    Validate an OAuth2/OIDC URL to prevent SSRF attacks.

    Args:
        url: The URL to validate
        context: Context for error messages

    Raises:
        OAuth2Error: If the URL fails validation
    """
    if not url or not url.strip():
        raise OAuth2Error(f"{context} URL is empty")

    url = url.strip()

    # Parse the URL
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        raise OAuth2Error(f"Invalid {context} URL format: {e}")

    # Check scheme - only allow HTTPS in production
    if _is_production_environment():
        if parsed.scheme != "https":
            raise OAuth2Error(
                f"Invalid {context} URL scheme: {parsed.scheme}. "
                "Only https:// is allowed in production."
            )
    elif parsed.scheme not in ("https", "http"):
        raise OAuth2Error(f"Invalid {context} URL scheme: {parsed.scheme}")

    # Check for empty hostname
    if not parsed.hostname:
        raise OAuth2Error(f"{context} URL must have a hostname")

    hostname = parsed.hostname.lower()

    # Block localhost and internal hostnames
    blocked_hostnames = {
        "localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]",
        "metadata.google.internal", "metadata.google",
        "kubernetes.default", "kubernetes.default.svc",
    }

    if hostname in blocked_hostnames:
        raise OAuth2Error(f"Blocked hostname for {context}: {hostname}")

    # Block private IPs directly in URL
    try:
        if _is_private_ip(hostname):
            raise OAuth2Error(
                f"Private/internal IP addresses are not allowed for {context}: {hostname}"
            )
    except ValueError:
        pass  # Not an IP, continue with DNS resolution

    # Resolve hostname and check all IPs (in production)
    if _is_production_environment():
        try:
            addr_info = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
            for family, socktype, proto, canonname, sockaddr in addr_info:
                ip = sockaddr[0]
                if _is_private_ip(ip):
                    raise OAuth2Error(
                        f"Hostname {hostname} resolves to private/internal IP {ip}. "
                        f"This is not allowed for {context} endpoints in production."
                    )
        except socket.gaierror as e:
            raise OAuth2Error(f"Cannot resolve hostname {hostname}: {e}")

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509 import load_pem_x509_certificate
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

logger = logging.getLogger(__name__)


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

        Fetches the OpenID Connect discovery document from the issuer's
        .well-known/openid-configuration endpoint.

        Args:
            issuer: OIDC issuer URL
            client_id: OAuth2 client ID
            client_secret: OAuth2 client secret (optional for public clients)

        Returns:
            OIDCConfig populated from discovery document

        Raises:
            OAuth2Error: If the issuer URL is invalid or fails SSRF validation
        """
        # Validate issuer URL to prevent SSRF attacks
        _validate_oauth_url(issuer, "OIDC issuer")

        discovery_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"

        if not HTTPX_AVAILABLE:
            logger.warning("httpx not available, using default OIDC endpoints")
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

        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.get(discovery_url)
                response.raise_for_status()
                doc = response.json()

            logger.debug(f"Fetched OIDC discovery document from {discovery_url}")

            return cls(
                provider_name=doc.get("issuer", "oidc"),
                client_id=client_id,
                client_secret=client_secret,
                issuer=doc.get("issuer", issuer),
                authorization_endpoint=doc.get("authorization_endpoint", ""),
                token_endpoint=doc.get("token_endpoint", ""),
                userinfo_endpoint=doc.get("userinfo_endpoint", ""),
                revocation_endpoint=doc.get("revocation_endpoint", ""),
                jwks_uri=doc.get("jwks_uri", ""),
                end_session_endpoint=doc.get("end_session_endpoint", ""),
                scopes=doc.get("scopes_supported", ["openid", "profile", "email"]),
                claims_supported=doc.get("claims_supported", []),
                id_token_signing_alg=doc.get("id_token_signing_alg_values_supported", ["RS256"])[0]
                    if doc.get("id_token_signing_alg_values_supported") else "RS256",
            )

        except Exception as e:
            logger.warning(f"Failed to fetch OIDC discovery document: {e}, using defaults")
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
# JWKS Key Management
# =============================================================================

class JWKSKeyManager:
    """
    Manages JSON Web Key Sets (JWKS) for ID token verification.

    Fetches and caches public keys from OIDC provider's JWKS endpoint
    to enable cryptographic signature verification of ID tokens.
    """

    def __init__(self, jwks_uri: str, cache_ttl_seconds: int = 3600):
        """
        Initialize JWKS key manager.

        Args:
            jwks_uri: URL of the JWKS endpoint
            cache_ttl_seconds: How long to cache keys (default: 1 hour)
        """
        self.jwks_uri = jwks_uri
        self.cache_ttl_seconds = cache_ttl_seconds
        self._keys: Dict[str, Any] = {}
        self._last_fetch: Optional[datetime] = None
        self._lock = threading.Lock()

    def _is_cache_valid(self) -> bool:
        """Check if cached keys are still valid."""
        if self._last_fetch is None:
            return False
        age = (datetime.utcnow() - self._last_fetch).total_seconds()
        return age < self.cache_ttl_seconds

    def _fetch_jwks(self) -> Dict[str, Any]:
        """Fetch JWKS from the provider."""
        if not HTTPX_AVAILABLE:
            raise OAuth2ConfigError("httpx is required for JWKS verification")

        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.get(self.jwks_uri)
                response.raise_for_status()
                return response.json()
        except Exception as e:
            logger.error(f"Failed to fetch JWKS from {self.jwks_uri}: {e}")
            raise OAuth2TokenError(f"Failed to fetch JWKS: {e}")

    def _parse_rsa_key(self, jwk: Dict[str, Any]) -> Any:
        """Parse an RSA public key from JWK format."""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise OAuth2ConfigError("cryptography library is required for JWT verification")

        # Decode the modulus (n) and exponent (e)
        n_bytes = base64.urlsafe_b64decode(jwk["n"] + "==")
        e_bytes = base64.urlsafe_b64decode(jwk["e"] + "==")

        n = int.from_bytes(n_bytes, byteorder="big")
        e = int.from_bytes(e_bytes, byteorder="big")

        # Construct the RSA public key
        public_numbers = rsa.RSAPublicNumbers(e, n)
        return public_numbers.public_key(default_backend())

    def _parse_ec_key(self, jwk: Dict[str, Any]) -> Any:
        """Parse an EC public key from JWK format."""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise OAuth2ConfigError("cryptography library is required for JWT verification")

        crv = jwk.get("crv", "P-256")
        x_bytes = base64.urlsafe_b64decode(jwk["x"] + "==")
        y_bytes = base64.urlsafe_b64decode(jwk["y"] + "==")

        x = int.from_bytes(x_bytes, byteorder="big")
        y = int.from_bytes(y_bytes, byteorder="big")

        # Map curve names to cryptography curves
        curve_map = {
            "P-256": ec.SECP256R1(),
            "P-384": ec.SECP384R1(),
            "P-521": ec.SECP521R1(),
        }

        curve = curve_map.get(crv)
        if curve is None:
            raise OAuth2TokenError(f"Unsupported EC curve: {crv}")

        public_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)
        return public_numbers.public_key(default_backend())

    def get_key(self, kid: str, force_refresh: bool = False) -> Any:
        """
        Get a public key by key ID.

        Args:
            kid: Key ID from the JWT header
            force_refresh: Force a refresh of the JWKS cache

        Returns:
            Public key object for signature verification

        Raises:
            OAuth2TokenError: If key not found
        """
        with self._lock:
            # Check cache first
            if not force_refresh and self._is_cache_valid() and kid in self._keys:
                return self._keys[kid]

            # Fetch fresh JWKS
            jwks = self._fetch_jwks()

            # Parse and cache all keys
            self._keys = {}
            for jwk in jwks.get("keys", []):
                key_id = jwk.get("kid")
                if not key_id:
                    continue

                kty = jwk.get("kty")
                try:
                    if kty == "RSA":
                        self._keys[key_id] = {
                            "key": self._parse_rsa_key(jwk),
                            "alg": jwk.get("alg", "RS256"),
                        }
                    elif kty == "EC":
                        self._keys[key_id] = {
                            "key": self._parse_ec_key(jwk),
                            "alg": jwk.get("alg", "ES256"),
                        }
                    # Skip unsupported key types silently
                except Exception as e:
                    logger.warning(f"Failed to parse JWK with kid={key_id}: {e}")
                    continue

            self._last_fetch = datetime.utcnow()

            if kid not in self._keys:
                # Key not found - could be rotation, try one more refresh
                if not force_refresh:
                    return self.get_key(kid, force_refresh=True)
                raise OAuth2TokenError(f"Key not found in JWKS: {kid}")

            return self._keys[kid]

    def verify_signature(
        self,
        header: Dict[str, Any],
        signed_content: bytes,
        signature: bytes,
    ) -> bool:
        """
        Verify a JWT signature using the appropriate key from JWKS.

        Args:
            header: JWT header containing kid and alg
            signed_content: The signed content (header.payload)
            signature: The signature bytes

        Returns:
            True if signature is valid

        Raises:
            OAuth2TokenError: If verification fails
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            raise OAuth2ConfigError("cryptography library is required for JWT verification")

        kid = header.get("kid")
        alg = header.get("alg", "RS256")

        if not kid:
            raise OAuth2TokenError("JWT header missing 'kid' claim")

        # Validate algorithm to prevent algorithm confusion attacks
        allowed_algs = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
        if alg not in allowed_algs:
            raise OAuth2TokenError(f"Unsupported or dangerous algorithm: {alg}")

        key_info = self.get_key(kid)
        public_key = key_info["key"]

        try:
            if alg.startswith("RS"):
                # RSA signature verification
                hash_alg = {
                    "RS256": hashes.SHA256(),
                    "RS384": hashes.SHA384(),
                    "RS512": hashes.SHA512(),
                }[alg]

                public_key.verify(
                    signature,
                    signed_content,
                    padding.PKCS1v15(),
                    hash_alg,
                )
            elif alg.startswith("ES"):
                # ECDSA signature verification
                hash_alg = {
                    "ES256": hashes.SHA256(),
                    "ES384": hashes.SHA384(),
                    "ES512": hashes.SHA512(),
                }[alg]

                public_key.verify(
                    signature,
                    signed_content,
                    ec.ECDSA(hash_alg),
                )
            else:
                raise OAuth2TokenError(f"Unsupported algorithm: {alg}")

            return True

        except Exception as e:
            raise OAuth2TokenError(f"Signature verification failed: {e}")


# =============================================================================
# OAuth2 Provider
# =============================================================================

class OAuth2Provider:
    """
    OAuth2 provider integration.

    Handles OAuth2 authorization flow and token management.
    Uses httpx for HTTP requests when available.
    """

    def __init__(self, config: OAuth2Config):
        """
        Initialize OAuth2 provider.

        Args:
            config: OAuth2 configuration
        """
        self.config = config
        self._states: Dict[str, OAuth2State] = {}
        self._states_lock = threading.RLock()  # Protect state dictionary from race conditions
        self._http_client: Optional[Any] = None

    def _get_http_client(self) -> Any:
        """Get or create HTTP client."""
        if self._http_client is None and HTTPX_AVAILABLE:
            self._http_client = httpx.Client(
                timeout=httpx.Timeout(30.0, connect=10.0),
                follow_redirects=False,  # OAuth redirects should be handled explicitly
            )
        return self._http_client

    def close(self) -> None:
        """Close HTTP client."""
        if self._http_client is not None:
            self._http_client.close()
            self._http_client = None

    def __enter__(self) -> "OAuth2Provider":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.close()

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
        with self._states_lock:
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

        # Use constant-time comparison to prevent timing attacks
        # First, find if state exists using constant-time lookup
        stored_state: Optional[OAuth2State] = None
        state_key: Optional[str] = None

        with self._states_lock:
            for key, value in self._states.items():
                # Use hmac.compare_digest for constant-time string comparison
                # This prevents timing attacks that could reveal valid state values
                if hmac.compare_digest(key.encode("utf-8"), state.encode("utf-8")):
                    stored_state = value
                    state_key = key
                    break

            if stored_state is None:
                raise OAuth2Error("Invalid or expired state parameter")

            if stored_state.is_expired():
                del self._states[state_key]
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

        Args:
            code: Authorization code
            state: State object from authorization

        Returns:
            OAuth2Token with access and refresh tokens

        Raises:
            OAuth2TokenError: If token exchange fails
        """
        # Clean up used state
        with self._states_lock:
            if state.state in self._states:
                del self._states[state.state]

        # Build token request
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": state.redirect_uri,
            "client_id": self.config.client_id,
        }

        # Add client secret if available
        if self.config.client_secret:
            token_data["client_secret"] = self.config.client_secret

        # Add PKCE code verifier if used
        if state.code_verifier:
            token_data["code_verifier"] = state.code_verifier

        if not HTTPX_AVAILABLE:
            # In production, fail rather than returning simulated tokens
            if _is_production_environment():
                raise OAuth2Error(
                    "httpx library is required for OAuth2 token exchange in production. "
                    "Install with: pip install httpx"
                )
            # Fall back to simulated response for testing/development only
            logger.warning(
                "httpx not available, returning simulated OAuth2 token. "
                "This is ONLY acceptable for development/testing."
            )
            return OAuth2Token(
                access_token=f"simulated_access_token_{secrets.token_hex(16)}",
                token_type="Bearer",
                expires_in=3600,
                refresh_token=f"simulated_refresh_token_{secrets.token_hex(16)}",
                scope=" ".join(state.scopes),
            )

        client = self._get_http_client()
        try:
            response = client.post(
                self.config.token_endpoint,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            if response.status_code >= 400:
                error_data = response.json() if response.content else {}
                error_msg = error_data.get("error_description", error_data.get("error", "Unknown error"))
                raise OAuth2TokenError(f"Token exchange failed: {error_msg}")

            token_response = response.json()
            logger.debug("Successfully exchanged authorization code for tokens")

            return OAuth2Token(
                access_token=token_response.get("access_token", ""),
                token_type=token_response.get("token_type", "Bearer"),
                expires_in=token_response.get("expires_in", 3600),
                refresh_token=token_response.get("refresh_token"),
                scope=token_response.get("scope", " ".join(state.scopes)),
                id_token=token_response.get("id_token"),
            )

        except httpx.RequestError as e:
            raise OAuth2TokenError(f"Token exchange request failed: {e}")

    def refresh_token(self, refresh_token: str) -> OAuth2Token:
        """
        Refresh an access token.

        Args:
            refresh_token: Refresh token

        Returns:
            New OAuth2Token

        Raises:
            OAuth2TokenError: If refresh fails
        """
        token_data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.config.client_id,
        }

        if self.config.client_secret:
            token_data["client_secret"] = self.config.client_secret

        if not HTTPX_AVAILABLE:
            if _is_production_environment():
                raise OAuth2Error(
                    "httpx library is required for OAuth2 token refresh in production. "
                    "Install with: pip install httpx"
                )
            logger.warning(
                "httpx not available, returning simulated refreshed token. "
                "This is ONLY acceptable for development/testing."
            )
            return OAuth2Token(
                access_token=f"refreshed_access_token_{secrets.token_hex(16)}",
                token_type="Bearer",
                expires_in=3600,
                refresh_token=f"new_refresh_token_{secrets.token_hex(16)}",
            )

        client = self._get_http_client()
        try:
            response = client.post(
                self.config.token_endpoint,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            if response.status_code >= 400:
                error_data = response.json() if response.content else {}
                error_msg = error_data.get("error_description", error_data.get("error", "Unknown error"))
                raise OAuth2TokenError(f"Token refresh failed: {error_msg}")

            token_response = response.json()
            logger.debug("Successfully refreshed access token")

            return OAuth2Token(
                access_token=token_response.get("access_token", ""),
                token_type=token_response.get("token_type", "Bearer"),
                expires_in=token_response.get("expires_in", 3600),
                refresh_token=token_response.get("refresh_token", refresh_token),
                scope=token_response.get("scope", ""),
                id_token=token_response.get("id_token"),
            )

        except httpx.RequestError as e:
            raise OAuth2TokenError(f"Token refresh request failed: {e}")

    def revoke_token(self, token: str, token_type_hint: str = "access_token") -> bool:
        """
        Revoke a token.

        Args:
            token: Token to revoke
            token_type_hint: Type of token (access_token or refresh_token)

        Returns:
            True if revoked successfully
        """
        if not self.config.revocation_endpoint:
            logger.warning("No revocation endpoint configured")
            return True  # Silently succeed if no endpoint

        revoke_data = {
            "token": token,
            "token_type_hint": token_type_hint,
            "client_id": self.config.client_id,
        }

        if self.config.client_secret:
            revoke_data["client_secret"] = self.config.client_secret

        if not HTTPX_AVAILABLE:
            logger.warning("httpx not available, simulating token revocation")
            return True

        client = self._get_http_client()
        try:
            response = client.post(
                self.config.revocation_endpoint,
                data=revoke_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            # Revocation endpoints typically return 200 even if token is invalid
            if response.status_code == 200:
                logger.debug(f"Successfully revoked {token_type_hint}")
                return True

            logger.warning(f"Token revocation returned status {response.status_code}")
            return False

        except httpx.RequestError as e:
            logger.error(f"Token revocation request failed: {e}")
            return False

    def cleanup_expired_states(self) -> int:
        """Clean up expired state parameters."""
        with self._states_lock:
            expired = [s for s, state in self._states.items() if state.is_expired()]
            for s in expired:
                del self._states[s]
            return len(expired)

    def get_stats(self) -> Dict[str, Any]:
        """Get provider statistics."""
        with self._states_lock:
            pending_states = len(self._states)
        return {
            "provider_name": self.config.provider_name,
            "pending_states": pending_states,
            "pkce_required": self.config.pkce_required,
            "scopes": self.config.scopes,
        }


# =============================================================================
# OIDC Provider
# =============================================================================

class OIDCProvider(OAuth2Provider):
    """
    OpenID Connect provider integration.

    Extends OAuth2Provider with OIDC-specific functionality including
    cryptographic verification of ID tokens using JWKS.
    """

    def __init__(self, config: OIDCConfig, verify_signatures: bool = True):
        """
        Initialize OIDC provider.

        Args:
            config: OIDC configuration
            verify_signatures: Whether to verify ID token signatures (default: True)
                             Only set to False in development/testing environments
        """
        super().__init__(config)
        self.oidc_config = config
        self._verify_signatures = verify_signatures
        self._jwks_manager: Optional[JWKSKeyManager] = None

        if verify_signatures and config.jwks_uri:
            self._jwks_manager = JWKSKeyManager(config.jwks_uri)
        elif verify_signatures and not config.jwks_uri:
            logger.warning(
                "OIDC signature verification enabled but no jwks_uri configured. "
                "ID tokens will not have cryptographic verification."
            )

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

    def _decode_jwt_part(self, part: str) -> bytes:
        """Decode a base64url-encoded JWT part with proper padding."""
        # Add padding if needed
        pad_len = 4 - len(part) % 4
        if pad_len != 4:
            part += "=" * pad_len
        return base64.urlsafe_b64decode(part)

    def validate_id_token(self, id_token: str, nonce: Optional[str] = None) -> Dict[str, Any]:
        """
        Validate an ID token with cryptographic signature verification.

        Performs complete OIDC ID token validation including:
        - Cryptographic signature verification using JWKS
        - Algorithm validation to prevent confusion attacks
        - Issuer validation
        - Audience validation
        - Expiration check
        - Nonce validation (if provided)
        - Issued-at time validation

        Args:
            id_token: The ID token to validate
            nonce: Expected nonce value

        Returns:
            Validated claims

        Raises:
            OAuth2TokenError: If validation fails
        """
        try:
            # Decode JWT parts (header.payload.signature)
            parts = id_token.split(".")
            if len(parts) != 3:
                raise OAuth2TokenError("Invalid ID token format: expected 3 parts")

            header_b64, payload_b64, signature_b64 = parts

            # Decode header
            header = json.loads(self._decode_jwt_part(header_b64))

            # Validate algorithm - prevent algorithm confusion attacks
            alg = header.get("alg", "")
            allowed_algorithms = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}

            # CRITICAL: Never accept "none" algorithm or HMAC algorithms for ID tokens
            if alg == "none":
                raise OAuth2TokenError("Algorithm 'none' is not allowed for ID tokens")
            if alg.startswith("HS"):
                raise OAuth2TokenError(
                    f"HMAC algorithms ({alg}) are not allowed for ID tokens from OIDC providers. "
                    "This may indicate an algorithm confusion attack."
                )
            if alg not in allowed_algorithms:
                raise OAuth2TokenError(f"Unsupported algorithm: {alg}")

            # Verify cryptographic signature if JWKS manager is available
            if self._verify_signatures and self._jwks_manager:
                signed_content = f"{header_b64}.{payload_b64}".encode("utf-8")
                signature = self._decode_jwt_part(signature_b64)

                self._jwks_manager.verify_signature(header, signed_content, signature)
                logger.debug("ID token signature verified successfully")

            elif self._verify_signatures and not self._jwks_manager:
                logger.warning(
                    "ID token signature verification skipped: no JWKS manager configured. "
                    "Configure jwks_uri for production deployments."
                )

            # Decode payload
            claims = json.loads(self._decode_jwt_part(payload_b64))

            # Validate issuer
            if self.oidc_config.issuer:
                if claims.get("iss") != self.oidc_config.issuer:
                    raise OAuth2TokenError(
                        f"Invalid issuer: expected '{self.oidc_config.issuer}', "
                        f"got '{claims.get('iss')}'"
                    )

            # Validate audience
            aud = claims.get("aud")
            if isinstance(aud, list):
                if self.config.client_id not in aud:
                    raise OAuth2TokenError(f"Client ID not in audience: {aud}")
                # If multiple audiences, azp claim must be present and match client_id
                if len(aud) > 1:
                    azp = claims.get("azp")
                    if azp and azp != self.config.client_id:
                        raise OAuth2TokenError(f"Invalid authorized party (azp): {azp}")
            elif aud != self.config.client_id:
                raise OAuth2TokenError(f"Invalid audience: {aud}")

            # Validate expiration (required claim)
            exp = claims.get("exp")
            if exp is None:
                raise OAuth2TokenError("ID token missing required 'exp' claim")
            # Validate timestamp is a number in valid range
            if not isinstance(exp, (int, float)):
                raise OAuth2TokenError("ID token 'exp' claim is not a valid timestamp")
            # Valid Unix timestamp range: 0 to year 3000 approximately
            if exp < 0 or exp > 32503680000:  # Jan 1, 3000 UTC
                raise OAuth2TokenError("ID token 'exp' timestamp is out of valid range")
            if datetime.utcfromtimestamp(exp) < datetime.utcnow():
                raise OAuth2TokenError("ID token has expired")

            # Validate issued-at time (iat) - token shouldn't be from far future
            iat = claims.get("iat")
            if iat is not None:
                if not isinstance(iat, (int, float)):
                    raise OAuth2TokenError("ID token 'iat' claim is not a valid timestamp")
                if iat < 0 or iat > 32503680000:  # Jan 1, 3000 UTC
                    raise OAuth2TokenError("ID token 'iat' timestamp is out of valid range")
                iat_time = datetime.utcfromtimestamp(iat)
                # Allow 5 minutes of clock skew
                if iat_time > datetime.utcnow() + timedelta(minutes=5):
                    raise OAuth2TokenError("ID token issued-at time is in the future")

            # Validate nonce if provided (required if sent in auth request)
            if nonce:
                if claims.get("nonce") != nonce:
                    raise OAuth2TokenError("Invalid nonce - possible replay attack")
            elif self.oidc_config.require_nonce and "nonce" not in claims:
                raise OAuth2TokenError("ID token missing required 'nonce' claim")

            logger.debug("ID token validated successfully")
            return claims

        except OAuth2TokenError:
            raise
        except json.JSONDecodeError as e:
            raise OAuth2TokenError(f"Invalid JSON in ID token: {e}")
        except Exception as e:
            raise OAuth2TokenError(f"Failed to validate ID token: {e}")

    def get_userinfo(self, access_token: str) -> OIDCUserInfo:
        """
        Fetch user info from the userinfo endpoint.

        Args:
            access_token: Access token

        Returns:
            OIDCUserInfo with user claims

        Raises:
            OAuth2Error: If request fails
        """
        if not self.oidc_config.userinfo_endpoint:
            raise OAuth2Error("No userinfo endpoint configured")

        if not HTTPX_AVAILABLE:
            if _is_production_environment():
                raise OAuth2Error(
                    "httpx library is required for OIDC userinfo in production. "
                    "Install with: pip install httpx"
                )
            logger.warning(
                "httpx not available, returning simulated userinfo. "
                "This is ONLY acceptable for development/testing."
            )
            return OIDCUserInfo(
                sub=f"user_{secrets.token_hex(8)}",
                email="user@example.com",
                email_verified=True,
                name="Simulated User",
            )

        client = self._get_http_client()
        try:
            response = client.get(
                self.oidc_config.userinfo_endpoint,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )

            if response.status_code >= 400:
                raise OAuth2Error(f"Userinfo request failed: {response.status_code}")

            claims = response.json()
            logger.debug("Successfully fetched userinfo")
            return OIDCUserInfo.from_claims(claims)

        except httpx.RequestError as e:
            raise OAuth2Error(f"Userinfo request failed: {e}")

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
