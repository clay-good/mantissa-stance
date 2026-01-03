"""
Unit tests for APIGatewayCollector.

Tests cover:
- REST API collection with mocked boto3 responses
- HTTP/WebSocket API collection (v2)
- Network exposure detection (EDGE, REGIONAL, PRIVATE)
- Authorization and WAF configuration
- Resource policy analysis
- Stage configuration and logging
- Error handling for API failures
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from stance.collectors.aws_apigateway import APIGatewayCollector
from stance.models import (
    AssetCollection,
    NETWORK_EXPOSURE_INTERNET,
    NETWORK_EXPOSURE_INTERNAL,
)


class TestAPIGatewayCollector:
    """Tests for APIGatewayCollector."""

    def test_apigateway_collector_init(self):
        """Test APIGatewayCollector can be initialized."""
        collector = APIGatewayCollector()
        assert collector.collector_name == "aws_apigateway"
        assert "aws_apigateway_rest_api" in collector.resource_types
        assert "aws_apigateway_http_api" in collector.resource_types

    def test_apigateway_collector_collect_rest_apis(self, mock_apigw_client):
        """Test REST API collection with mock response."""
        with patch.object(
            APIGatewayCollector, "_get_client", return_value=mock_apigw_client
        ):
            collector = APIGatewayCollector()
            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            rest_apis = [
                a for a in assets if a.resource_type == "aws_apigateway_rest_api"
            ]
            assert len(rest_apis) >= 1

            api = rest_apis[0]
            assert api.name == "test-rest-api"
            assert api.cloud_provider == "aws"
            assert api.region == "us-east-1"

    def test_apigateway_collector_edge_endpoint(self, mock_apigw_client_edge):
        """Test EDGE endpoint API has internet exposure."""
        with patch.object(
            APIGatewayCollector, "_get_client", return_value=mock_apigw_client_edge
        ):
            collector = APIGatewayCollector()
            assets = collector.collect()

            api = next(
                (a for a in assets if a.resource_type == "aws_apigateway_rest_api"),
                None,
            )
            assert api is not None
            assert api.network_exposure == NETWORK_EXPOSURE_INTERNET
            assert api.raw_config["is_edge_optimized"] is True

    def test_apigateway_collector_regional_endpoint(self, mock_apigw_client_regional):
        """Test REGIONAL endpoint API has internet exposure."""
        with patch.object(
            APIGatewayCollector, "_get_client", return_value=mock_apigw_client_regional
        ):
            collector = APIGatewayCollector()
            assets = collector.collect()

            api = next(
                (a for a in assets if a.resource_type == "aws_apigateway_rest_api"),
                None,
            )
            assert api is not None
            assert api.network_exposure == NETWORK_EXPOSURE_INTERNET
            assert api.raw_config["is_regional"] is True

    def test_apigateway_collector_private_endpoint(self, mock_apigw_client_private):
        """Test PRIVATE endpoint API has internal exposure."""
        with patch.object(
            APIGatewayCollector, "_get_client", return_value=mock_apigw_client_private
        ):
            collector = APIGatewayCollector()
            assets = collector.collect()

            api = next(
                (a for a in assets if a.resource_type == "aws_apigateway_rest_api"),
                None,
            )
            assert api is not None
            assert api.network_exposure == NETWORK_EXPOSURE_INTERNAL
            assert api.raw_config["is_private"] is True

    def test_apigateway_collector_with_authorizers(self, mock_apigw_client_with_auth):
        """Test API with authorizers is detected."""
        with patch.object(
            APIGatewayCollector, "_get_client", return_value=mock_apigw_client_with_auth
        ):
            collector = APIGatewayCollector()
            assets = collector.collect()

            api = next(
                (a for a in assets if a.resource_type == "aws_apigateway_rest_api"),
                None,
            )
            assert api is not None
            assert api.raw_config["has_authorizers"] is True
            assert "COGNITO_USER_POOLS" in api.raw_config["authorizer_types"]

    def test_apigateway_collector_with_waf(self, mock_apigw_client_with_waf):
        """Test API with WAF is detected."""
        with patch.object(
            APIGatewayCollector, "_get_client", return_value=mock_apigw_client_with_waf
        ):
            collector = APIGatewayCollector()
            assets = collector.collect()

            api = next(
                (a for a in assets if a.resource_type == "aws_apigateway_rest_api"),
                None,
            )
            assert api is not None
            assert api.raw_config["has_waf"] is True

    def test_apigateway_collector_http_api(self, mock_apigwv2_client):
        """Test HTTP API collection."""
        with patch.object(
            APIGatewayCollector, "_get_client", return_value=mock_apigwv2_client
        ):
            collector = APIGatewayCollector()
            assets = collector.collect()

            http_apis = [
                a for a in assets if a.resource_type == "aws_apigateway_http_api"
            ]
            assert len(http_apis) >= 1

            api = http_apis[0]
            assert api.name == "test-http-api"
            assert api.raw_config["api_type"] == "HTTP"

    def test_apigateway_collector_http_api_cors(self, mock_apigwv2_client_cors):
        """Test HTTP API CORS configuration detection."""
        with patch.object(
            APIGatewayCollector, "_get_client", return_value=mock_apigwv2_client_cors
        ):
            collector = APIGatewayCollector()
            assets = collector.collect()

            api = next(
                (a for a in assets if a.resource_type == "aws_apigateway_http_api"),
                None,
            )
            assert api is not None
            assert api.raw_config["has_cors"] is True
            assert api.raw_config["allows_all_origins"] is True

    def test_apigateway_collector_handles_empty_response(
        self, mock_apigw_client_empty
    ):
        """Test handling of empty API list."""
        with patch.object(
            APIGatewayCollector, "_get_client", return_value=mock_apigw_client_empty
        ):
            collector = APIGatewayCollector()
            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            assert len(assets) == 0

    def test_apigateway_collector_handles_api_error(self, mock_apigw_client_error):
        """Test graceful handling of API errors."""
        with patch.object(
            APIGatewayCollector, "_get_client", return_value=mock_apigw_client_error
        ):
            collector = APIGatewayCollector()
            # Should not raise, but return empty collection
            assets = collector.collect()
            assert isinstance(assets, AssetCollection)
            assert len(assets) == 0

    def test_apigateway_collector_tags_extraction(self, mock_apigw_client):
        """Test that tags are extracted correctly."""
        with patch.object(
            APIGatewayCollector, "_get_client", return_value=mock_apigw_client
        ):
            collector = APIGatewayCollector()
            assets = collector.collect()

            api = next(
                (a for a in assets if a.resource_type == "aws_apigateway_rest_api"),
                None,
            )
            assert api is not None
            assert api.tags == {"environment": "production", "team": "api"}


# Helper functions to create mock objects


def _create_mock_rest_api(
    api_id: str = "abc123",
    name: str = "test-rest-api",
    endpoint_types: list[str] | None = None,
    tags: dict | None = None,
) -> dict:
    """Create a mock REST API response."""
    return {
        "id": api_id,
        "name": name,
        "description": "Test API",
        "createdDate": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "version": "1.0",
        "apiKeySource": "HEADER",
        "endpointConfiguration": {
            "types": endpoint_types or ["REGIONAL"],
            "vpcEndpointIds": [],
        },
        "tags": tags or {"environment": "production", "team": "api"},
        "disableExecuteApiEndpoint": False,
    }


def _create_mock_http_api(
    api_id: str = "http123",
    name: str = "test-http-api",
    protocol_type: str = "HTTP",
    cors_config: dict | None = None,
    tags: dict | None = None,
) -> dict:
    """Create a mock HTTP API response."""
    result = {
        "ApiId": api_id,
        "Name": name,
        "Description": "Test HTTP API",
        "ProtocolType": protocol_type,
        "CreatedDate": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "ApiEndpoint": f"https://{api_id}.execute-api.us-east-1.amazonaws.com",
        "DisableExecuteApiEndpoint": False,
        "Tags": tags or {"environment": "production"},
    }
    if cors_config:
        result["CorsConfiguration"] = cors_config
    return result


def _create_mock_stage(
    stage_name: str = "prod",
    has_logging: bool = False,
    web_acl_arn: str | None = None,
) -> dict:
    """Create a mock stage response."""
    stage = {
        "stageName": stage_name,
        "deploymentId": "deploy123",
        "description": "Production stage",
        "cacheClusterEnabled": False,
        "createdDate": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "lastUpdatedDate": datetime(2024, 1, 15, tzinfo=timezone.utc),
        "tracingEnabled": False,
        "tags": {},
    }
    if has_logging:
        stage["accessLogSettings"] = {
            "destinationArn": "arn:aws:logs:us-east-1:123456789012:log-group:api-logs",
            "format": "$requestId",
        }
    return stage


def _create_mock_authorizer(
    auth_id: str = "auth123",
    name: str = "cognito-authorizer",
    auth_type: str = "COGNITO_USER_POOLS",
) -> dict:
    """Create a mock authorizer response."""
    return {
        "id": auth_id,
        "name": name,
        "type": auth_type,
        "providerARNs": ["arn:aws:cognito-idp:us-east-1:123456789012:userpool/pool1"],
    }


def _create_mock_apigw_client(
    rest_apis: list | None = None,
    stages: list | None = None,
    authorizers: list | None = None,
    web_acl_arn: str | None = None,
) -> MagicMock:
    """Create a mock API Gateway client."""
    client = MagicMock()

    # Mock get_rest_apis
    if rest_apis is None:
        rest_apis = [_create_mock_rest_api()]
    client.get_rest_apis.return_value = {"items": rest_apis}

    # Mock get_rest_api (for policy)
    client.get_rest_api.return_value = {"policy": None}

    # Mock get_stages
    if stages is None:
        stages = [_create_mock_stage()]
    client.get_stages.return_value = {"item": stages}

    # Mock get_authorizers
    if authorizers is None:
        authorizers = []
    client.get_authorizers.return_value = {"items": authorizers}

    # Mock get_documentation_parts
    client.get_documentation_parts.return_value = {"items": []}

    # Mock HTTP API calls (v2)
    client.get_apis.return_value = {"Items": []}

    # Mock WAF
    if web_acl_arn:
        client.get_web_acl_for_resource.return_value = {
            "WebACL": {"ARN": web_acl_arn}
        }
    else:
        client.get_web_acl_for_resource.return_value = {}

    return client


def _create_mock_apigwv2_client(
    http_apis: list | None = None,
    stages: list | None = None,
    authorizers: list | None = None,
) -> MagicMock:
    """Create a mock API Gateway v2 client."""
    client = MagicMock()

    # Mock REST API calls (v1) - empty for v2 client
    client.get_rest_apis.return_value = {"items": []}
    client.get_rest_api.return_value = {"policy": None}
    client.get_stages.return_value = {"item": []}
    client.get_authorizers.return_value = {"items": []}
    client.get_documentation_parts.return_value = {"items": []}
    client.get_web_acl_for_resource.return_value = {}

    # Mock HTTP API calls (v2)
    if http_apis is None:
        http_apis = [_create_mock_http_api()]
    client.get_apis.return_value = {"Items": http_apis}

    if stages is None:
        stages = [{"StageName": "$default", "AutoDeploy": True}]

    if authorizers is None:
        authorizers = []

    # Override get_stages for v2
    def get_stages_mock(**kwargs):
        if "ApiId" in kwargs:
            return {"Items": stages}
        return {"item": []}

    client.get_stages.side_effect = get_stages_mock

    # Override get_authorizers for v2
    def get_authorizers_mock(**kwargs):
        if "ApiId" in kwargs:
            return {"Items": authorizers}
        return {"items": []}

    client.get_authorizers.side_effect = get_authorizers_mock

    client.get_integrations.return_value = {"Items": []}

    return client


# Fixtures


@pytest.fixture
def mock_apigw_client():
    """Return a mocked API Gateway client with sample responses."""
    return _create_mock_apigw_client()


@pytest.fixture
def mock_apigw_client_edge():
    """Return a mocked client for an EDGE endpoint API."""
    api = _create_mock_rest_api(endpoint_types=["EDGE"])
    return _create_mock_apigw_client(rest_apis=[api])


@pytest.fixture
def mock_apigw_client_regional():
    """Return a mocked client for a REGIONAL endpoint API."""
    api = _create_mock_rest_api(endpoint_types=["REGIONAL"])
    return _create_mock_apigw_client(rest_apis=[api])


@pytest.fixture
def mock_apigw_client_private():
    """Return a mocked client for a PRIVATE endpoint API."""
    api = _create_mock_rest_api(endpoint_types=["PRIVATE"])
    api["endpointConfiguration"]["vpcEndpointIds"] = ["vpce-123456"]
    return _create_mock_apigw_client(rest_apis=[api])


@pytest.fixture
def mock_apigw_client_with_auth():
    """Return a mocked client with authorizers configured."""
    authorizers = [_create_mock_authorizer()]
    return _create_mock_apigw_client(authorizers=authorizers)


@pytest.fixture
def mock_apigw_client_with_waf():
    """Return a mocked client with WAF configured."""
    stages = [_create_mock_stage(
        web_acl_arn="arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-acl/abc123"
    )]
    client = _create_mock_apigw_client(stages=stages)
    client.get_web_acl_for_resource.return_value = {
        "WebACL": {
            "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-acl/abc123"
        }
    }
    return client


@pytest.fixture
def mock_apigwv2_client():
    """Return a mocked API Gateway v2 client."""
    return _create_mock_apigwv2_client()


@pytest.fixture
def mock_apigwv2_client_cors():
    """Return a mocked v2 client with CORS configured."""
    api = _create_mock_http_api(
        cors_config={
            "AllowOrigins": ["*"],
            "AllowMethods": ["GET", "POST"],
            "AllowHeaders": ["Content-Type"],
            "AllowCredentials": False,
        }
    )
    return _create_mock_apigwv2_client(http_apis=[api])


@pytest.fixture
def mock_apigw_client_empty():
    """Return a mocked client with no APIs."""
    client = MagicMock()
    client.get_rest_apis.return_value = {"items": []}
    client.get_apis.return_value = {"Items": []}
    return client


@pytest.fixture
def mock_apigw_client_error():
    """Return a mocked client that raises an error."""
    client = MagicMock()
    client.get_rest_apis.side_effect = Exception("API Error: Access Denied")
    client.get_apis.side_effect = Exception("API Error: Access Denied")
    return client
