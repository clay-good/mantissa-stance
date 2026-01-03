"""
Unit tests for Web API Collectors endpoints.

Tests the REST API endpoints for collector management including listing,
provider information, registry inspection, and availability checks.
"""

from __future__ import annotations

import json
from typing import Any
from unittest import mock

import pytest


class TestCollectorsListEndpoint:
    """Tests for /api/collectors/list endpoint."""

    def test_list_all_collectors(self):
        """Test listing all collectors."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_collector_metadata = StanceRequestHandler._get_collector_metadata.__get__(handler)
        handler._collectors_list = StanceRequestHandler._collectors_list.__get__(handler)

        result = handler._collectors_list({})

        assert "collectors" in result
        assert "total" in result
        assert result["total"] > 0
        assert result["filter"] is None

    def test_list_collectors_filtered_by_provider(self):
        """Test listing collectors filtered by provider."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_collector_metadata = StanceRequestHandler._get_collector_metadata.__get__(handler)
        handler._collectors_list = StanceRequestHandler._collectors_list.__get__(handler)

        result = handler._collectors_list({"provider": ["aws"]})

        assert "collectors" in result
        assert result["filter"] == "aws"
        # All collectors should be AWS
        for c in result["collectors"]:
            assert c["provider"] == "aws"

    def test_list_collectors_empty_provider(self):
        """Test listing collectors with unavailable provider."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_collector_metadata = StanceRequestHandler._get_collector_metadata.__get__(handler)
        handler._collectors_list = StanceRequestHandler._collectors_list.__get__(handler)

        # Mock GCP not available
        with mock.patch("stance.collectors.GCP_COLLECTORS_AVAILABLE", False):
            result = handler._collectors_list({"provider": ["gcp"]})

            assert result["collectors"] == []
            assert result["total"] == 0


class TestCollectorsInfoEndpoint:
    """Tests for /api/collectors/info endpoint."""

    def test_info_missing_name(self):
        """Test info endpoint without name parameter."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_collector_metadata = StanceRequestHandler._get_collector_metadata.__get__(handler)
        handler._get_collector_resource_types = StanceRequestHandler._get_collector_resource_types.__get__(handler)
        handler._collectors_info = StanceRequestHandler._collectors_info.__get__(handler)

        result = handler._collectors_info({})

        assert "error" in result
        assert "name" in result["error"]

    def test_info_collector_not_found(self):
        """Test info endpoint with nonexistent collector."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_collector_metadata = StanceRequestHandler._get_collector_metadata.__get__(handler)
        handler._get_collector_resource_types = StanceRequestHandler._get_collector_resource_types.__get__(handler)
        handler._collectors_info = StanceRequestHandler._collectors_info.__get__(handler)

        result = handler._collectors_info({"name": ["nonexistent"]})

        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_info_collector_found(self):
        """Test info endpoint with valid collector."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_collector_metadata = StanceRequestHandler._get_collector_metadata.__get__(handler)
        handler._get_collector_resource_types = StanceRequestHandler._get_collector_resource_types.__get__(handler)
        handler._collectors_info = StanceRequestHandler._collectors_info.__get__(handler)

        result = handler._collectors_info({"name": ["aws_iam"]})

        assert result["name"] == "aws_iam"
        assert result["provider"] == "aws"
        assert result["category"] == "identity"
        assert result["available"] is True
        assert "resource_types" in result


class TestCollectorsProvidersEndpoint:
    """Tests for /api/collectors/providers endpoint."""

    def test_providers_list(self):
        """Test providers endpoint."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._collectors_providers = StanceRequestHandler._collectors_providers.__get__(handler)

        result = handler._collectors_providers({})

        assert "providers" in result
        assert "total" in result
        assert "available" in result
        assert result["total"] == 4

        # Check providers
        provider_names = [p["provider"] for p in result["providers"]]
        assert "aws" in provider_names
        assert "gcp" in provider_names
        assert "azure" in provider_names
        assert "kubernetes" in provider_names

    def test_providers_aws_always_available(self):
        """Test that AWS is always available."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._collectors_providers = StanceRequestHandler._collectors_providers.__get__(handler)

        result = handler._collectors_providers({})

        aws = [p for p in result["providers"] if p["provider"] == "aws"][0]
        assert aws["available"] is True
        assert aws["collectors"] == 10


class TestCollectorsResourcesEndpoint:
    """Tests for /api/collectors/resources endpoint."""

    def test_resources_all(self):
        """Test resources endpoint without filters."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._collectors_resources = StanceRequestHandler._collectors_resources.__get__(handler)

        result = handler._collectors_resources({})

        assert "resources" in result
        assert "total" in result
        assert "filters" in result
        assert result["filters"]["provider"] is None
        assert result["filters"]["collector"] is None

    def test_resources_filtered_by_provider(self):
        """Test resources endpoint filtered by provider."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._collectors_resources = StanceRequestHandler._collectors_resources.__get__(handler)

        result = handler._collectors_resources({"provider": ["aws"]})

        assert result["filters"]["provider"] == "aws"
        # All resources should be from AWS
        for r in result["resources"]:
            assert r["provider"] == "aws"

    def test_resources_filtered_by_collector(self):
        """Test resources endpoint filtered by collector."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._collectors_resources = StanceRequestHandler._collectors_resources.__get__(handler)

        result = handler._collectors_resources({"collector": ["aws_iam"]})

        assert result["filters"]["collector"] == "aws_iam"
        for r in result["resources"]:
            assert r["collector"] == "aws_iam"


class TestCollectorsRegistryEndpoint:
    """Tests for /api/collectors/registry endpoint."""

    def test_registry(self):
        """Test registry endpoint."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._collectors_registry = StanceRequestHandler._collectors_registry.__get__(handler)

        result = handler._collectors_registry({})

        assert "registry" in result
        assert "total" in result
        assert "aws" in result["registry"]
        assert isinstance(result["registry"]["aws"], list)


class TestCollectorsAvailabilityEndpoint:
    """Tests for /api/collectors/availability endpoint."""

    def test_availability(self):
        """Test availability endpoint."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._collectors_availability = StanceRequestHandler._collectors_availability.__get__(handler)

        result = handler._collectors_availability({})

        assert "availability" in result
        assert len(result["availability"]) == 4

        # Check AWS always available
        aws = [a for a in result["availability"] if a["provider"] == "aws"][0]
        assert aws["available"] is True
        assert "reason" in aws
        assert "install" in aws

    def test_availability_shows_install_commands(self):
        """Test that availability shows install commands."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._collectors_availability = StanceRequestHandler._collectors_availability.__get__(handler)

        result = handler._collectors_availability({})

        for item in result["availability"]:
            assert "install" in item
            assert item["install"].startswith("pip install")


class TestCollectorsCategoriesEndpoint:
    """Tests for /api/collectors/categories endpoint."""

    def test_categories(self):
        """Test categories endpoint."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._collectors_categories = StanceRequestHandler._collectors_categories.__get__(handler)

        result = handler._collectors_categories({})

        assert "categories" in result
        assert "total" in result
        assert result["total"] == 10

        category_names = [c["category"] for c in result["categories"]]
        assert "identity" in category_names
        assert "storage" in category_names
        assert "compute" in category_names
        assert "security" in category_names

    def test_categories_structure(self):
        """Test categories have proper structure."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._collectors_categories = StanceRequestHandler._collectors_categories.__get__(handler)

        result = handler._collectors_categories({})

        for cat in result["categories"]:
            assert "category" in cat
            assert "description" in cat
            assert "examples" in cat
            assert isinstance(cat["examples"], list)


class TestCollectorsCountEndpoint:
    """Tests for /api/collectors/count endpoint."""

    def test_count(self):
        """Test count endpoint."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._collectors_count = StanceRequestHandler._collectors_count.__get__(handler)

        result = handler._collectors_count({})

        assert "counts" in result
        assert "total" in result
        assert result["total"] >= 0

        # Check structure
        for count in result["counts"]:
            assert "provider" in count
            assert "count" in count
            assert "available" in count


class TestCollectorsStatsEndpoint:
    """Tests for /api/collectors/stats endpoint."""

    def test_stats(self):
        """Test stats endpoint."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_collector_metadata = StanceRequestHandler._get_collector_metadata.__get__(handler)
        handler._collectors_stats = StanceRequestHandler._collectors_stats.__get__(handler)

        result = handler._collectors_stats({})

        assert "total_collectors" in result
        assert "available_providers" in result
        assert "total_providers" in result
        assert "categories" in result
        assert "by_provider" in result
        assert "sdk_availability" in result

    def test_stats_sdk_availability(self):
        """Test stats shows SDK availability."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_collector_metadata = StanceRequestHandler._get_collector_metadata.__get__(handler)
        handler._collectors_stats = StanceRequestHandler._collectors_stats.__get__(handler)

        result = handler._collectors_stats({})

        assert "boto3" in result["sdk_availability"]
        assert result["sdk_availability"]["boto3"] is True


class TestCollectorsStatusEndpoint:
    """Tests for /api/collectors/status endpoint."""

    def test_status(self):
        """Test status endpoint."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._collectors_status = StanceRequestHandler._collectors_status.__get__(handler)

        result = handler._collectors_status({})

        assert result["module"] == "collectors"
        assert "components" in result
        assert "providers" in result
        assert "capabilities" in result

    def test_status_components(self):
        """Test status shows required components."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._collectors_status = StanceRequestHandler._collectors_status.__get__(handler)

        result = handler._collectors_status({})

        assert "BaseCollector" in result["components"]
        assert "CollectorResult" in result["components"]
        assert "CollectorRunner" in result["components"]
        assert "COLLECTOR_REGISTRY" in result["components"]

    def test_status_capabilities(self):
        """Test status shows capabilities."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._collectors_status = StanceRequestHandler._collectors_status.__get__(handler)

        result = handler._collectors_status({})

        capabilities = result["capabilities"]
        assert "multi_provider_support" in capabilities
        assert "pagination_handling" in capabilities
        assert "error_handling" in capabilities


class TestCollectorsSummaryEndpoint:
    """Tests for /api/collectors/summary endpoint."""

    def test_summary(self):
        """Test summary endpoint."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_collector_metadata = StanceRequestHandler._get_collector_metadata.__get__(handler)
        handler._collectors_summary = StanceRequestHandler._collectors_summary.__get__(handler)

        result = handler._collectors_summary({})

        assert "overview" in result
        assert "categories" in result
        assert "features" in result
        assert "architecture" in result

    def test_summary_overview(self):
        """Test summary overview section."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_collector_metadata = StanceRequestHandler._get_collector_metadata.__get__(handler)
        handler._collectors_summary = StanceRequestHandler._collectors_summary.__get__(handler)

        result = handler._collectors_summary({})

        overview = result["overview"]
        assert "description" in overview
        assert "total_collectors" in overview
        assert "providers" in overview

    def test_summary_features(self):
        """Test summary features section."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_collector_metadata = StanceRequestHandler._get_collector_metadata.__get__(handler)
        handler._collectors_summary = StanceRequestHandler._collectors_summary.__get__(handler)

        result = handler._collectors_summary({})

        features = result["features"]
        assert isinstance(features, list)
        assert len(features) > 0


class TestGetCollectorMetadata:
    """Tests for _get_collector_metadata helper."""

    def test_metadata_structure(self):
        """Test metadata structure."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_collector_metadata = StanceRequestHandler._get_collector_metadata.__get__(handler)

        result = handler._get_collector_metadata()

        assert "aws" in result
        assert "gcp" in result
        assert "azure" in result
        assert "kubernetes" in result

    def test_aws_collectors_present(self):
        """Test AWS collectors are always present."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_collector_metadata = StanceRequestHandler._get_collector_metadata.__get__(handler)

        result = handler._get_collector_metadata()

        assert len(result["aws"]) == 10

        aws_names = [c["name"] for c in result["aws"]]
        expected = ["aws_iam", "aws_s3", "aws_ec2", "aws_security", "aws_rds",
                    "aws_lambda", "aws_dynamodb", "aws_apigateway", "aws_ecr", "aws_eks"]
        for name in expected:
            assert name in aws_names


class TestGetCollectorResourceTypes:
    """Tests for _get_collector_resource_types helper."""

    def test_get_resource_types_aws_iam(self):
        """Test getting resource types for aws_iam collector."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_collector_resource_types = StanceRequestHandler._get_collector_resource_types.__get__(handler)

        result = handler._get_collector_resource_types("aws_iam")

        assert isinstance(result, list)

    def test_get_resource_types_nonexistent(self):
        """Test getting resource types for nonexistent collector."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_collector_resource_types = StanceRequestHandler._get_collector_resource_types.__get__(handler)

        result = handler._get_collector_resource_types("nonexistent")

        assert result == []


class TestCollectorsApiIntegration:
    """Integration tests for collectors API endpoints."""

    def test_all_endpoints_callable(self):
        """Test all endpoints are callable."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        # Bind all methods
        handler._get_collector_metadata = StanceRequestHandler._get_collector_metadata.__get__(handler)
        handler._get_collector_resource_types = StanceRequestHandler._get_collector_resource_types.__get__(handler)
        handler._collectors_list = StanceRequestHandler._collectors_list.__get__(handler)
        handler._collectors_info = StanceRequestHandler._collectors_info.__get__(handler)
        handler._collectors_providers = StanceRequestHandler._collectors_providers.__get__(handler)
        handler._collectors_resources = StanceRequestHandler._collectors_resources.__get__(handler)
        handler._collectors_registry = StanceRequestHandler._collectors_registry.__get__(handler)
        handler._collectors_availability = StanceRequestHandler._collectors_availability.__get__(handler)
        handler._collectors_categories = StanceRequestHandler._collectors_categories.__get__(handler)
        handler._collectors_count = StanceRequestHandler._collectors_count.__get__(handler)
        handler._collectors_stats = StanceRequestHandler._collectors_stats.__get__(handler)
        handler._collectors_status = StanceRequestHandler._collectors_status.__get__(handler)
        handler._collectors_summary = StanceRequestHandler._collectors_summary.__get__(handler)

        # Test each endpoint
        endpoints = [
            ("_collectors_list", {}),
            ("_collectors_info", {"name": ["aws_iam"]}),
            ("_collectors_providers", {}),
            ("_collectors_resources", {}),
            ("_collectors_registry", {}),
            ("_collectors_availability", {}),
            ("_collectors_categories", {}),
            ("_collectors_count", {}),
            ("_collectors_stats", {}),
            ("_collectors_status", {}),
            ("_collectors_summary", {}),
        ]

        for method_name, params in endpoints:
            method = getattr(handler, method_name)
            result = method(params)
            assert isinstance(result, dict), f"{method_name} should return dict"

    def test_json_serializable(self):
        """Test all endpoint responses are JSON serializable."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        # Bind all methods
        handler._get_collector_metadata = StanceRequestHandler._get_collector_metadata.__get__(handler)
        handler._get_collector_resource_types = StanceRequestHandler._get_collector_resource_types.__get__(handler)
        handler._collectors_list = StanceRequestHandler._collectors_list.__get__(handler)
        handler._collectors_info = StanceRequestHandler._collectors_info.__get__(handler)
        handler._collectors_providers = StanceRequestHandler._collectors_providers.__get__(handler)
        handler._collectors_resources = StanceRequestHandler._collectors_resources.__get__(handler)
        handler._collectors_registry = StanceRequestHandler._collectors_registry.__get__(handler)
        handler._collectors_availability = StanceRequestHandler._collectors_availability.__get__(handler)
        handler._collectors_categories = StanceRequestHandler._collectors_categories.__get__(handler)
        handler._collectors_count = StanceRequestHandler._collectors_count.__get__(handler)
        handler._collectors_stats = StanceRequestHandler._collectors_stats.__get__(handler)
        handler._collectors_status = StanceRequestHandler._collectors_status.__get__(handler)
        handler._collectors_summary = StanceRequestHandler._collectors_summary.__get__(handler)

        endpoints = [
            ("_collectors_list", {}),
            ("_collectors_info", {"name": ["aws_iam"]}),
            ("_collectors_providers", {}),
            ("_collectors_resources", {}),
            ("_collectors_registry", {}),
            ("_collectors_availability", {}),
            ("_collectors_categories", {}),
            ("_collectors_count", {}),
            ("_collectors_stats", {}),
            ("_collectors_status", {}),
            ("_collectors_summary", {}),
        ]

        for method_name, params in endpoints:
            method = getattr(handler, method_name)
            result = method(params)
            try:
                json.dumps(result)
            except (TypeError, ValueError) as e:
                pytest.fail(f"{method_name} response not JSON serializable: {e}")
