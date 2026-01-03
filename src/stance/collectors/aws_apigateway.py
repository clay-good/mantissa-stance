"""
AWS API Gateway collector for Mantissa Stance.

Collects API Gateway REST APIs (v1), HTTP APIs (v2), and WebSocket APIs
for security posture assessment.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.collectors.base import BaseCollector
from stance.models import (
    Asset,
    AssetCollection,
    NETWORK_EXPOSURE_INTERNET,
    NETWORK_EXPOSURE_INTERNAL,
)

logger = logging.getLogger(__name__)


class APIGatewayCollector(BaseCollector):
    """
    Collects AWS API Gateway resources and configurations.

    Gathers API Gateway REST APIs, HTTP APIs, and WebSocket APIs with their
    security configurations including:
    - API endpoint types (EDGE, REGIONAL, PRIVATE)
    - Authorization settings (IAM, Cognito, Lambda authorizers)
    - WAF associations
    - Resource policies
    - Stage configurations
    - Throttling settings
    - Client certificates
    - VPC endpoint associations

    All API calls are read-only.
    """

    collector_name = "aws_apigateway"
    resource_types = [
        "aws_apigateway_rest_api",
        "aws_apigateway_http_api",
        "aws_apigateway_stage",
    ]

    def collect(self) -> AssetCollection:
        """
        Collect all API Gateway resources.

        Returns:
            Collection of API Gateway assets
        """
        assets: list[Asset] = []

        # Collect REST APIs (API Gateway v1)
        try:
            assets.extend(self._collect_rest_apis())
        except Exception as e:
            logger.warning(f"Failed to collect REST APIs: {e}")

        # Collect HTTP and WebSocket APIs (API Gateway v2)
        try:
            assets.extend(self._collect_http_apis())
        except Exception as e:
            logger.warning(f"Failed to collect HTTP/WebSocket APIs: {e}")

        return AssetCollection(assets)

    def _collect_rest_apis(self) -> list[Asset]:
        """Collect REST APIs (API Gateway v1)."""
        apigw_client = self._get_client("apigateway")
        assets: list[Asset] = []
        now = self._now()

        try:
            # REST APIs use position-based pagination
            position = None
            while True:
                kwargs: dict[str, Any] = {"limit": 500}
                if position:
                    kwargs["position"] = position

                response = apigw_client.get_rest_apis(**kwargs)
                items = response.get("items", [])

                for api in items:
                    api_id = api["id"]
                    api_name = api.get("name", api_id)

                    # Get API resource policy
                    resource_policy = self._get_rest_api_policy(api_id)

                    # Get stages for this API
                    stages = self._get_rest_api_stages(api_id)

                    # Get authorizers
                    authorizers = self._get_rest_api_authorizers(api_id)

                    # Get documentation parts count
                    documentation = self._get_rest_api_documentation(api_id)

                    # Determine endpoint configuration
                    endpoint_config = api.get("endpointConfiguration", {})
                    endpoint_types = endpoint_config.get("types", [])
                    vpc_endpoint_ids = endpoint_config.get("vpcEndpointIds", [])
                    is_private = "PRIVATE" in endpoint_types

                    # Check if API has WAF associated (via stage)
                    has_waf = any(
                        stage.get("web_acl_arn") for stage in stages
                    )

                    # Determine network exposure
                    network_exposure = self._determine_rest_api_network_exposure(
                        endpoint_types=endpoint_types,
                        resource_policy=resource_policy,
                        is_private=is_private,
                    )

                    # Check authorization settings
                    has_authorizers = len(authorizers) > 0
                    authorizer_types = list(set(
                        auth.get("type", "") for auth in authorizers
                    ))

                    # Extract tags
                    tags = api.get("tags", {})

                    raw_config: dict[str, Any] = {
                        "api_id": api_id,
                        "api_name": api_name,
                        "api_type": "REST",
                        "description": api.get("description"),
                        "created_date": (
                            api.get("createdDate").isoformat()
                            if api.get("createdDate")
                            else None
                        ),
                        "version": api.get("version"),
                        "api_key_source": api.get("apiKeySource", "HEADER"),
                        "binary_media_types": api.get("binaryMediaTypes", []),
                        "minimum_compression_size": api.get("minimumCompressionSize"),
                        "disable_execute_api_endpoint": api.get(
                            "disableExecuteApiEndpoint", False
                        ),
                        # Endpoint configuration
                        "endpoint_types": endpoint_types,
                        "is_edge_optimized": "EDGE" in endpoint_types,
                        "is_regional": "REGIONAL" in endpoint_types,
                        "is_private": is_private,
                        "vpc_endpoint_ids": vpc_endpoint_ids,
                        # Policy
                        "resource_policy": resource_policy,
                        "has_resource_policy": bool(resource_policy),
                        "allows_public_access": self._policy_allows_public_access(
                            resource_policy
                        ),
                        # Stages
                        "stages": stages,
                        "stage_count": len(stages),
                        "has_stages": len(stages) > 0,
                        # Authorizers
                        "authorizers": authorizers,
                        "has_authorizers": has_authorizers,
                        "authorizer_types": authorizer_types,
                        # Security
                        "has_waf": has_waf,
                        # Documentation
                        "has_documentation": documentation.get("count", 0) > 0,
                        "documentation_count": documentation.get("count", 0),
                        # Warnings (deprecated)
                        "warnings": api.get("warnings", []),
                    }

                    # Build ARN
                    api_arn = self._build_arn(
                        "apigateway",
                        "restapis",
                        api_id,
                        region=self._region,
                        account_id="",
                    )

                    asset = Asset(
                        id=api_arn,
                        cloud_provider="aws",
                        account_id=self.account_id,
                        region=self._region,
                        resource_type="aws_apigateway_rest_api",
                        name=api_name,
                        tags=tags,
                        network_exposure=network_exposure,
                        created_at=api.get("createdDate"),
                        last_seen=now,
                        raw_config=raw_config,
                    )
                    assets.append(asset)

                # Check for more pages
                position = response.get("position")
                if not position:
                    break

        except Exception as e:
            logger.error(f"Error listing REST APIs: {e}")
            raise

        return assets

    def _collect_http_apis(self) -> list[Asset]:
        """Collect HTTP and WebSocket APIs (API Gateway v2)."""
        apigwv2_client = self._get_client("apigatewayv2")
        assets: list[Asset] = []
        now = self._now()

        try:
            # HTTP/WebSocket APIs use NextToken pagination
            next_token = None
            while True:
                kwargs: dict[str, Any] = {"MaxResults": "100"}
                if next_token:
                    kwargs["NextToken"] = next_token

                response = apigwv2_client.get_apis(**kwargs)
                items = response.get("Items", [])

                for api in items:
                    api_id = api["ApiId"]
                    api_name = api.get("Name", api_id)
                    protocol_type = api.get("ProtocolType", "HTTP")

                    # Get stages for this API
                    stages = self._get_http_api_stages(api_id)

                    # Get authorizers
                    authorizers = self._get_http_api_authorizers(api_id)

                    # Get integrations count
                    integrations = self._get_http_api_integrations(api_id)

                    # Determine network exposure
                    network_exposure = self._determine_http_api_network_exposure(api)

                    # Check for CORS configuration
                    cors_config = api.get("CorsConfiguration", {})
                    has_cors = bool(cors_config)
                    allows_all_origins = "*" in cors_config.get("AllowOrigins", [])

                    # Authorization settings
                    has_authorizers = len(authorizers) > 0
                    authorizer_types = list(set(
                        auth.get("AuthorizerType", "") for auth in authorizers
                    ))

                    # Extract tags
                    tags = api.get("Tags", {})

                    raw_config: dict[str, Any] = {
                        "api_id": api_id,
                        "api_name": api_name,
                        "api_type": protocol_type,
                        "description": api.get("Description"),
                        "created_date": api.get("CreatedDate"),
                        "version": api.get("Version"),
                        "api_endpoint": api.get("ApiEndpoint"),
                        "route_selection_expression": api.get(
                            "RouteSelectionExpression"
                        ),
                        "api_gateway_managed": api.get("ApiGatewayManaged", False),
                        "disable_execute_api_endpoint": api.get(
                            "DisableExecuteApiEndpoint", False
                        ),
                        "disable_schema_validation": api.get(
                            "DisableSchemaValidation", False
                        ),
                        # CORS
                        "cors_configuration": cors_config,
                        "has_cors": has_cors,
                        "allows_all_origins": allows_all_origins,
                        "cors_allow_origins": cors_config.get("AllowOrigins", []),
                        "cors_allow_methods": cors_config.get("AllowMethods", []),
                        "cors_allow_headers": cors_config.get("AllowHeaders", []),
                        "cors_allow_credentials": cors_config.get(
                            "AllowCredentials", False
                        ),
                        "cors_max_age": cors_config.get("MaxAge"),
                        # Stages
                        "stages": stages,
                        "stage_count": len(stages),
                        "has_stages": len(stages) > 0,
                        # Authorizers
                        "authorizers": authorizers,
                        "has_authorizers": has_authorizers,
                        "authorizer_types": authorizer_types,
                        # Integrations
                        "integration_count": len(integrations),
                        "has_integrations": len(integrations) > 0,
                        # Import info
                        "import_info": api.get("ImportInfo", []),
                        # Warnings
                        "warnings": api.get("Warnings", []),
                    }

                    # Build ARN
                    api_arn = self._build_arn(
                        "apigateway",
                        "apis",
                        api_id,
                        region=self._region,
                        account_id="",
                    )

                    asset = Asset(
                        id=api_arn,
                        cloud_provider="aws",
                        account_id=self.account_id,
                        region=self._region,
                        resource_type="aws_apigateway_http_api",
                        name=api_name,
                        tags=tags,
                        network_exposure=network_exposure,
                        created_at=api.get("CreatedDate"),
                        last_seen=now,
                        raw_config=raw_config,
                    )
                    assets.append(asset)

                # Check for more pages
                next_token = response.get("NextToken")
                if not next_token:
                    break

        except Exception as e:
            logger.error(f"Error listing HTTP/WebSocket APIs: {e}")
            raise

        return assets

    def _get_rest_api_policy(self, api_id: str) -> dict[str, Any] | None:
        """Get resource policy for a REST API."""
        apigw_client = self._get_client("apigateway")
        try:
            response = apigw_client.get_rest_api(restApiId=api_id)
            policy_str = response.get("policy")
            if policy_str:
                import json
                # Policy is a JSON string that may be escaped
                try:
                    return json.loads(policy_str)
                except json.JSONDecodeError:
                    # Try unescaping
                    return json.loads(policy_str.replace("\\", ""))
            return None
        except Exception as e:
            logger.debug(f"Could not get policy for API {api_id}: {e}")
            return None

    def _get_rest_api_stages(self, api_id: str) -> list[dict[str, Any]]:
        """Get stages for a REST API."""
        apigw_client = self._get_client("apigateway")
        try:
            response = apigw_client.get_stages(restApiId=api_id)
            stages = []
            for stage in response.get("item", []):
                # Get WAF association for stage
                web_acl_arn = self._get_stage_waf(api_id, stage.get("stageName", ""))

                stage_config = {
                    "stage_name": stage.get("stageName"),
                    "deployment_id": stage.get("deploymentId"),
                    "description": stage.get("description"),
                    "cache_cluster_enabled": stage.get("cacheClusterEnabled", False),
                    "cache_cluster_size": stage.get("cacheClusterSize"),
                    "cache_cluster_status": stage.get("cacheClusterStatus"),
                    "client_certificate_id": stage.get("clientCertificateId"),
                    "has_client_certificate": bool(stage.get("clientCertificateId")),
                    "documentation_version": stage.get("documentationVersion"),
                    "created_date": (
                        stage.get("createdDate").isoformat()
                        if stage.get("createdDate")
                        else None
                    ),
                    "last_updated_date": (
                        stage.get("lastUpdatedDate").isoformat()
                        if stage.get("lastUpdatedDate")
                        else None
                    ),
                    # Access logging
                    "access_log_settings": stage.get("accessLogSettings", {}),
                    "has_access_logging": bool(stage.get("accessLogSettings")),
                    # Canary settings
                    "canary_settings": stage.get("canarySettings", {}),
                    "has_canary": bool(stage.get("canarySettings")),
                    # Tracing
                    "tracing_enabled": stage.get("tracingEnabled", False),
                    # Method settings
                    "method_settings": stage.get("methodSettings", {}),
                    # Variables
                    "variables": list(stage.get("variables", {}).keys()),
                    # WAF
                    "web_acl_arn": web_acl_arn,
                    "has_waf": bool(web_acl_arn),
                    # Tags
                    "tags": stage.get("tags", {}),
                }
                stages.append(stage_config)
            return stages
        except Exception as e:
            logger.debug(f"Could not get stages for API {api_id}: {e}")
            return []

    def _get_rest_api_authorizers(self, api_id: str) -> list[dict[str, Any]]:
        """Get authorizers for a REST API."""
        apigw_client = self._get_client("apigateway")
        try:
            response = apigw_client.get_authorizers(restApiId=api_id)
            authorizers = []
            for auth in response.get("items", []):
                auth_config = {
                    "authorizer_id": auth.get("id"),
                    "name": auth.get("name"),
                    "type": auth.get("type"),
                    "provider_arns": auth.get("providerARNs", []),
                    "auth_type": auth.get("authType"),
                    "authorizer_uri": auth.get("authorizerUri"),
                    "authorizer_credentials": bool(auth.get("authorizerCredentials")),
                    "identity_source": auth.get("identitySource"),
                    "identity_validation_expression": auth.get(
                        "identityValidationExpression"
                    ),
                    "authorizer_result_ttl_in_seconds": auth.get(
                        "authorizerResultTtlInSeconds"
                    ),
                }
                authorizers.append(auth_config)
            return authorizers
        except Exception as e:
            logger.debug(f"Could not get authorizers for API {api_id}: {e}")
            return []

    def _get_rest_api_documentation(self, api_id: str) -> dict[str, Any]:
        """Get documentation info for a REST API."""
        apigw_client = self._get_client("apigateway")
        try:
            response = apigw_client.get_documentation_parts(
                restApiId=api_id, limit=1
            )
            # Just get count, not full docs
            return {"count": len(response.get("items", []))}
        except Exception as e:
            logger.debug(f"Could not get documentation for API {api_id}: {e}")
            return {"count": 0}

    def _get_stage_waf(self, api_id: str, stage_name: str) -> str | None:
        """Get WAF WebACL ARN associated with a stage."""
        wafv2_client = self._get_client("wafv2")
        try:
            # Build the stage ARN
            stage_arn = (
                f"arn:aws:apigateway:{self._region}::"
                f"/restapis/{api_id}/stages/{stage_name}"
            )
            response = wafv2_client.get_web_acl_for_resource(
                ResourceArn=stage_arn
            )
            web_acl = response.get("WebACL", {})
            return web_acl.get("ARN")
        except Exception as e:
            logger.debug(f"Could not get WAF for stage {api_id}/{stage_name}: {e}")
            return None

    def _get_http_api_stages(self, api_id: str) -> list[dict[str, Any]]:
        """Get stages for an HTTP/WebSocket API."""
        apigwv2_client = self._get_client("apigatewayv2")
        try:
            response = apigwv2_client.get_stages(ApiId=api_id)
            stages = []
            for stage in response.get("Items", []):
                stage_config = {
                    "stage_name": stage.get("StageName"),
                    "description": stage.get("Description"),
                    "deployment_id": stage.get("DeploymentId"),
                    "api_gateway_managed": stage.get("ApiGatewayManaged", False),
                    "auto_deploy": stage.get("AutoDeploy", False),
                    "created_date": stage.get("CreatedDate"),
                    "last_updated_date": stage.get("LastUpdatedDate"),
                    "client_certificate_id": stage.get("ClientCertificateId"),
                    "has_client_certificate": bool(stage.get("ClientCertificateId")),
                    # Default route settings
                    "default_route_settings": stage.get("DefaultRouteSettings", {}),
                    "throttling_burst_limit": stage.get(
                        "DefaultRouteSettings", {}
                    ).get("ThrottlingBurstLimit"),
                    "throttling_rate_limit": stage.get(
                        "DefaultRouteSettings", {}
                    ).get("ThrottlingRateLimit"),
                    "logging_level": stage.get("DefaultRouteSettings", {}).get(
                        "LoggingLevel"
                    ),
                    "data_trace_enabled": stage.get("DefaultRouteSettings", {}).get(
                        "DataTraceEnabled", False
                    ),
                    "detailed_metrics_enabled": stage.get(
                        "DefaultRouteSettings", {}
                    ).get("DetailedMetricsEnabled", False),
                    # Access log settings
                    "access_log_settings": stage.get("AccessLogSettings", {}),
                    "has_access_logging": bool(stage.get("AccessLogSettings")),
                    # Route settings
                    "route_settings": stage.get("RouteSettings", {}),
                    # Stage variables
                    "stage_variables": list(stage.get("StageVariables", {}).keys()),
                    # Tags
                    "tags": stage.get("Tags", {}),
                }
                stages.append(stage_config)
            return stages
        except Exception as e:
            logger.debug(f"Could not get stages for HTTP API {api_id}: {e}")
            return []

    def _get_http_api_authorizers(self, api_id: str) -> list[dict[str, Any]]:
        """Get authorizers for an HTTP/WebSocket API."""
        apigwv2_client = self._get_client("apigatewayv2")
        try:
            response = apigwv2_client.get_authorizers(ApiId=api_id)
            authorizers = []
            for auth in response.get("Items", []):
                auth_config = {
                    "authorizer_id": auth.get("AuthorizerId"),
                    "name": auth.get("Name"),
                    "authorizer_type": auth.get("AuthorizerType"),
                    "authorizer_uri": auth.get("AuthorizerUri"),
                    "authorizer_credentials_arn": auth.get("AuthorizerCredentialsArn"),
                    "enable_simple_responses": auth.get("EnableSimpleResponses", False),
                    "identity_source": auth.get("IdentitySource", []),
                    "identity_validation_expression": auth.get(
                        "IdentityValidationExpression"
                    ),
                    "jwt_configuration": auth.get("JwtConfiguration", {}),
                    "authorizer_payload_format_version": auth.get(
                        "AuthorizerPayloadFormatVersion"
                    ),
                    "authorizer_result_ttl_in_seconds": auth.get(
                        "AuthorizerResultTtlInSeconds"
                    ),
                }
                authorizers.append(auth_config)
            return authorizers
        except Exception as e:
            logger.debug(f"Could not get authorizers for HTTP API {api_id}: {e}")
            return []

    def _get_http_api_integrations(self, api_id: str) -> list[dict[str, Any]]:
        """Get integrations for an HTTP/WebSocket API."""
        apigwv2_client = self._get_client("apigatewayv2")
        try:
            response = apigwv2_client.get_integrations(ApiId=api_id)
            integrations = []
            for integ in response.get("Items", []):
                integ_config = {
                    "integration_id": integ.get("IntegrationId"),
                    "integration_type": integ.get("IntegrationType"),
                    "integration_method": integ.get("IntegrationMethod"),
                    "integration_uri": integ.get("IntegrationUri"),
                    "connection_type": integ.get("ConnectionType"),
                    "connection_id": integ.get("ConnectionId"),
                    "timeout_in_millis": integ.get("TimeoutInMillis"),
                    "payload_format_version": integ.get("PayloadFormatVersion"),
                }
                integrations.append(integ_config)
            return integrations
        except Exception as e:
            logger.debug(f"Could not get integrations for HTTP API {api_id}: {e}")
            return []

    def _determine_rest_api_network_exposure(
        self,
        endpoint_types: list[str],
        resource_policy: dict[str, Any] | None,
        is_private: bool,
    ) -> str:
        """Determine network exposure for a REST API."""
        # Private APIs are internal only
        if is_private:
            return NETWORK_EXPOSURE_INTERNAL

        # Check if resource policy restricts access
        if resource_policy and not self._policy_allows_public_access(resource_policy):
            return NETWORK_EXPOSURE_INTERNAL

        # EDGE and REGIONAL endpoints are internet-facing by default
        if "EDGE" in endpoint_types or "REGIONAL" in endpoint_types:
            return NETWORK_EXPOSURE_INTERNET

        return NETWORK_EXPOSURE_INTERNAL

    def _determine_http_api_network_exposure(self, api: dict[str, Any]) -> str:
        """Determine network exposure for an HTTP/WebSocket API."""
        # HTTP APIs don't have private endpoints like REST APIs
        # They are internet-facing unless disabled
        if api.get("DisableExecuteApiEndpoint", False):
            return NETWORK_EXPOSURE_INTERNAL

        # HTTP/WebSocket APIs are internet-facing by default
        return NETWORK_EXPOSURE_INTERNET

    def _policy_allows_public_access(
        self, policy: dict[str, Any] | None
    ) -> bool:
        """Check if resource policy allows public access."""
        if not policy:
            return True  # No policy = default open for non-private APIs

        statements = policy.get("Statement", [])
        for statement in statements:
            effect = statement.get("Effect", "").upper()
            principal = statement.get("Principal", {})

            # Check for explicit allow with public principal
            if effect == "ALLOW":
                if principal == "*":
                    # Check for condition that restricts access
                    condition = statement.get("Condition", {})
                    if not condition:
                        return True
                if isinstance(principal, dict):
                    aws_principal = principal.get("AWS", "")
                    if aws_principal == "*":
                        condition = statement.get("Condition", {})
                        if not condition:
                            return True

        return False
