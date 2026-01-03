"""
API Endpoint Discovery for API Security Testing.

Discovers and inventories API endpoints from cloud assets,
OpenAPI specifications, and other sources.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from stance.api_security.models import (
    APIEndpoint,
    APIProtocol,
    AuthenticationType,
)
from stance.models import Asset

logger = logging.getLogger(__name__)


@dataclass
class APIInventory:
    """Collection of discovered API endpoints."""

    endpoints: list[APIEndpoint] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    sources: list[str] = field(default_factory=list)

    # Statistics
    total_endpoints: int = 0
    public_endpoints: int = 0
    authenticated_endpoints: int = 0
    unauthenticated_endpoints: int = 0

    # By provider
    by_provider: dict[str, int] = field(default_factory=dict)

    # By protocol
    by_protocol: dict[str, int] = field(default_factory=dict)

    def add_endpoint(self, endpoint: APIEndpoint) -> None:
        """Add an endpoint to the inventory."""
        self.endpoints.append(endpoint)
        self._update_statistics()

    def _update_statistics(self) -> None:
        """Update inventory statistics."""
        self.total_endpoints = len(self.endpoints)
        self.public_endpoints = sum(1 for e in self.endpoints if e.is_public)
        self.authenticated_endpoints = sum(
            1 for e in self.endpoints if e.authentication_required
        )
        self.unauthenticated_endpoints = sum(
            1 for e in self.endpoints if not e.authentication_required
        )

        # Count by provider
        self.by_provider = {}
        for endpoint in self.endpoints:
            provider = endpoint.cloud_provider or "unknown"
            self.by_provider[provider] = self.by_provider.get(provider, 0) + 1

        # Count by protocol
        self.by_protocol = {}
        for endpoint in self.endpoints:
            protocol = endpoint.protocol.value
            self.by_protocol[protocol] = self.by_protocol.get(protocol, 0) + 1

    def get_public_endpoints(self) -> list[APIEndpoint]:
        """Get all public (internet-facing) endpoints."""
        return [e for e in self.endpoints if e.is_public]

    def get_unauthenticated_endpoints(self) -> list[APIEndpoint]:
        """Get endpoints without authentication."""
        return [e for e in self.endpoints if not e.authentication_required]

    def get_endpoints_by_provider(self, provider: str) -> list[APIEndpoint]:
        """Get endpoints for a specific cloud provider."""
        return [e for e in self.endpoints if e.cloud_provider == provider]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "summary": {
                "total_endpoints": self.total_endpoints,
                "public_endpoints": self.public_endpoints,
                "authenticated_endpoints": self.authenticated_endpoints,
                "unauthenticated_endpoints": self.unauthenticated_endpoints,
            },
            "by_provider": self.by_provider,
            "by_protocol": self.by_protocol,
            "discovered_at": self.discovered_at.isoformat(),
            "sources": self.sources,
            "endpoints": [e.to_dict() for e in self.endpoints],
        }


class APIDiscoverer:
    """
    Discovers API endpoints from various sources.

    Supports discovery from:
    - Cloud assets (AWS API Gateway, Azure API Management, GCP API Gateway)
    - OpenAPI/Swagger specifications
    - GraphQL introspection
    """

    def __init__(self):
        """Initialize the API discoverer."""
        self._inventory = APIInventory()

    def discover_from_assets(self, assets: list[Asset]) -> APIInventory:
        """
        Discover API endpoints from cloud assets.

        Args:
            assets: List of cloud assets to analyze

        Returns:
            APIInventory with discovered endpoints
        """
        inventory = APIInventory(sources=["cloud_assets"])

        for asset in assets:
            endpoint = self._asset_to_endpoint(asset)
            if endpoint:
                inventory.add_endpoint(endpoint)

        inventory._update_statistics()
        return inventory

    def _asset_to_endpoint(self, asset: Asset) -> APIEndpoint | None:
        """Convert a cloud asset to an API endpoint."""
        resource_type = asset.resource_type

        # AWS API Gateway REST API
        if resource_type == "aws_apigateway_rest_api":
            return self._convert_aws_rest_api(asset)

        # AWS API Gateway HTTP/WebSocket API
        if resource_type == "aws_apigateway_http_api":
            return self._convert_aws_http_api(asset)

        # Azure API Management
        if resource_type in ("azure_apim_api", "azure_api_management"):
            return self._convert_azure_apim(asset)

        # GCP API Gateway
        if resource_type in ("gcp_apigateway_api", "gcp_api_gateway"):
            return self._convert_gcp_api_gateway(asset)

        return None

    def _convert_aws_rest_api(self, asset: Asset) -> APIEndpoint:
        """Convert AWS REST API asset to APIEndpoint."""
        config = asset.raw_config or {}

        # Determine authentication type
        auth_type = AuthenticationType.NONE
        authorizers = config.get("authorizers", [])
        authorizer_types = config.get("authorizer_types", [])

        if authorizers:
            if "COGNITO_USER_POOLS" in authorizer_types:
                auth_type = AuthenticationType.COGNITO
            elif "REQUEST" in authorizer_types or "TOKEN" in authorizer_types:
                auth_type = AuthenticationType.LAMBDA
            elif "AWS_IAM" in authorizer_types:
                auth_type = AuthenticationType.IAM
            else:
                auth_type = AuthenticationType.CUSTOM

        # Check API key requirement
        requires_api_key = config.get("api_key_source") == "HEADER"

        # Determine if public
        is_public = not config.get("is_private", False)
        if config.get("allows_public_access") is False:
            is_public = False

        # Get stages
        stages = [s.get("stage_name", "") for s in config.get("stages", [])]

        # Check for rate limiting in stages
        has_rate_limiting = False
        rate_limit = None
        burst_limit = None
        for stage in config.get("stages", []):
            method_settings = stage.get("method_settings", {})
            if method_settings:
                has_rate_limiting = True
                # Get default throttling
                default_settings = method_settings.get("*/*", {})
                rate_limit = default_settings.get("throttlingRateLimit")
                burst_limit = default_settings.get("throttlingBurstLimit")
                break

        # Check logging
        access_logging = any(
            s.get("has_access_logging", False) for s in config.get("stages", [])
        )

        # Build endpoint URL
        api_id = config.get("api_id", "")
        region = asset.region
        url = f"https://{api_id}.execute-api.{region}.amazonaws.com"

        return APIEndpoint(
            id=asset.id,
            name=config.get("api_name", asset.name),
            url=url,
            protocol=APIProtocol.REST,
            cloud_provider="aws",
            account_id=asset.account_id,
            region=asset.region,
            resource_type=asset.resource_type,
            authentication_type=auth_type,
            authentication_required=len(authorizers) > 0 or requires_api_key,
            authorizers=authorizers,
            is_public=is_public,
            requires_api_key=requires_api_key,
            has_waf=config.get("has_waf", False),
            has_rate_limiting=has_rate_limiting,
            rate_limit=rate_limit,
            burst_limit=burst_limit,
            cors_enabled=False,  # REST APIs use CORS at method level
            access_logging_enabled=access_logging,
            has_documentation=config.get("has_documentation", False),
            stages=stages,
            tags=asset.tags,
            created_at=asset.created_at,
            raw_config=config,
        )

    def _convert_aws_http_api(self, asset: Asset) -> APIEndpoint:
        """Convert AWS HTTP/WebSocket API asset to APIEndpoint."""
        config = asset.raw_config or {}

        # Determine protocol
        api_type = config.get("api_type", "HTTP")
        if api_type == "WEBSOCKET":
            protocol = APIProtocol.WEBSOCKET
        else:
            protocol = APIProtocol.REST

        # Determine authentication type
        auth_type = AuthenticationType.NONE
        authorizers = config.get("authorizers", [])
        authorizer_types = config.get("authorizer_types", [])

        if authorizers:
            if "JWT" in authorizer_types:
                auth_type = AuthenticationType.JWT
            elif "REQUEST" in authorizer_types:
                auth_type = AuthenticationType.LAMBDA
            else:
                auth_type = AuthenticationType.CUSTOM

        # CORS configuration
        cors_enabled = config.get("has_cors", False)
        cors_origins = config.get("cors_allow_origins", [])
        cors_all_origins = config.get("allows_all_origins", False)
        cors_credentials = config.get("cors_allow_credentials", False)

        # Get stages
        stages = [s.get("stage_name", "") for s in config.get("stages", [])]

        # Check for rate limiting
        has_rate_limiting = False
        rate_limit = None
        burst_limit = None
        for stage in config.get("stages", []):
            if stage.get("throttling_rate_limit"):
                has_rate_limiting = True
                rate_limit = stage.get("throttling_rate_limit")
                burst_limit = stage.get("throttling_burst_limit")
                break

        # Check logging
        access_logging = any(
            s.get("has_access_logging", False) for s in config.get("stages", [])
        )

        return APIEndpoint(
            id=asset.id,
            name=config.get("api_name", asset.name),
            url=config.get("api_endpoint"),
            protocol=protocol,
            cloud_provider="aws",
            account_id=asset.account_id,
            region=asset.region,
            resource_type=asset.resource_type,
            authentication_type=auth_type,
            authentication_required=len(authorizers) > 0,
            authorizers=authorizers,
            is_public=not config.get("disable_execute_api_endpoint", False),
            has_rate_limiting=has_rate_limiting,
            rate_limit=rate_limit,
            burst_limit=burst_limit,
            cors_enabled=cors_enabled,
            cors_allow_origins=cors_origins,
            cors_allow_all_origins=cors_all_origins,
            cors_allow_credentials=cors_credentials,
            access_logging_enabled=access_logging,
            stages=stages,
            tags=asset.tags,
            created_at=asset.created_at,
            raw_config=config,
        )

    def _convert_azure_apim(self, asset: Asset) -> APIEndpoint:
        """Convert Azure API Management asset to APIEndpoint."""
        config = asset.raw_config or {}

        # Determine authentication
        auth_type = AuthenticationType.UNKNOWN
        auth_settings = config.get("authentication_settings", {})
        if auth_settings.get("oauth2"):
            auth_type = AuthenticationType.OAUTH2
        elif auth_settings.get("openid_connect"):
            auth_type = AuthenticationType.JWT
        elif config.get("subscription_required", False):
            auth_type = AuthenticationType.API_KEY

        return APIEndpoint(
            id=asset.id,
            name=config.get("display_name", asset.name),
            url=config.get("service_url"),
            protocol=APIProtocol.REST,
            cloud_provider="azure",
            account_id=asset.account_id,
            region=asset.region,
            resource_type=asset.resource_type,
            authentication_type=auth_type,
            authentication_required=config.get("subscription_required", False),
            is_public=config.get("is_public", True),
            requires_api_key=config.get("subscription_required", False),
            has_rate_limiting=config.get("has_rate_limiting", False),
            tags=asset.tags,
            created_at=asset.created_at,
            raw_config=config,
        )

    def _convert_gcp_api_gateway(self, asset: Asset) -> APIEndpoint:
        """Convert GCP API Gateway asset to APIEndpoint."""
        config = asset.raw_config or {}

        # GCP API Gateway typically uses service account authentication
        auth_type = AuthenticationType.UNKNOWN
        if config.get("managed_service"):
            auth_type = AuthenticationType.IAM

        return APIEndpoint(
            id=asset.id,
            name=config.get("display_name", asset.name),
            url=config.get("default_hostname"),
            protocol=APIProtocol.REST,
            cloud_provider="gcp",
            account_id=asset.account_id,
            region=asset.region,
            resource_type=asset.resource_type,
            authentication_type=auth_type,
            authentication_required=config.get("authentication_required", True),
            is_public=config.get("is_public", True),
            tags=asset.tags,
            created_at=asset.created_at,
            raw_config=config,
        )

    def discover_from_openapi(
        self,
        spec: dict[str, Any],
        source_name: str = "openapi",
    ) -> APIInventory:
        """
        Discover API endpoints from an OpenAPI specification.

        Args:
            spec: OpenAPI specification dictionary
            source_name: Name of the source for tracking

        Returns:
            APIInventory with discovered endpoints
        """
        inventory = APIInventory(sources=[source_name])

        # Get API info
        info = spec.get("info", {})
        api_title = info.get("title", "Unknown API")
        api_version = info.get("version", "1.0.0")

        # Get servers
        servers = spec.get("servers", [])
        base_url = servers[0].get("url", "") if servers else ""

        # Get security schemes
        security_schemes = spec.get("components", {}).get("securitySchemes", {})

        # Determine authentication type from security schemes
        auth_type = AuthenticationType.NONE
        for scheme_name, scheme in security_schemes.items():
            scheme_type = scheme.get("type", "")
            if scheme_type == "apiKey":
                auth_type = AuthenticationType.API_KEY
            elif scheme_type == "http":
                if scheme.get("scheme") == "bearer":
                    auth_type = AuthenticationType.BEARER
                elif scheme.get("scheme") == "basic":
                    auth_type = AuthenticationType.BASIC
            elif scheme_type == "oauth2":
                auth_type = AuthenticationType.OAUTH2
            elif scheme_type == "openIdConnect":
                auth_type = AuthenticationType.JWT

        # Get global security requirements
        global_security = spec.get("security", [])
        auth_required = len(global_security) > 0

        # Collect all HTTP methods from paths
        http_methods = set()
        paths = spec.get("paths", {})
        for path, path_item in paths.items():
            for method in ["get", "post", "put", "patch", "delete", "head", "options"]:
                if method in path_item:
                    http_methods.add(method.upper())

        endpoint = APIEndpoint(
            id=f"openapi:{api_title}:{api_version}",
            name=api_title,
            url=base_url,
            protocol=APIProtocol.REST,
            http_methods=list(http_methods),
            authentication_type=auth_type,
            authentication_required=auth_required,
            has_documentation=True,
            openapi_spec=spec,
            raw_config=spec,
        )

        inventory.add_endpoint(endpoint)
        inventory._update_statistics()

        return inventory

    def merge_inventories(self, *inventories: APIInventory) -> APIInventory:
        """Merge multiple inventories into one."""
        merged = APIInventory()
        seen_ids: set[str] = set()

        for inv in inventories:
            merged.sources.extend(inv.sources)
            for endpoint in inv.endpoints:
                if endpoint.id not in seen_ids:
                    merged.endpoints.append(endpoint)
                    seen_ids.add(endpoint.id)

        merged.sources = list(set(merged.sources))
        merged._update_statistics()

        return merged
