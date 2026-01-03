"""
Unit tests for Web API Cloud endpoints.

Tests the REST API endpoints for cloud provider management including listing,
validation, account info, and region discovery.
"""

from __future__ import annotations

import json
from typing import Any
from unittest import mock

import pytest


class TestCloudListEndpoint:
    """Tests for /api/cloud/list endpoint."""

    def test_list_providers(self):
        """Test listing all providers."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_cloud_provider_metadata = StanceRequestHandler._get_cloud_provider_metadata.__get__(handler)
        handler._cloud_list = StanceRequestHandler._cloud_list.__get__(handler)

        result = handler._cloud_list({})

        assert "providers" in result
        assert "total" in result
        assert result["total"] == 3

        provider_names = [p["name"] for p in result["providers"]]
        assert "aws" in provider_names
        assert "gcp" in provider_names
        assert "azure" in provider_names


class TestCloudInfoEndpoint:
    """Tests for /api/cloud/info endpoint."""

    def test_info_missing_provider(self):
        """Test info endpoint without provider parameter."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_credential_fields = StanceRequestHandler._get_credential_fields.__get__(handler)
        handler._get_default_region = StanceRequestHandler._get_default_region.__get__(handler)
        handler._get_storage_types = StanceRequestHandler._get_storage_types.__get__(handler)
        handler._cloud_info = StanceRequestHandler._cloud_info.__get__(handler)

        result = handler._cloud_info({})

        assert "error" in result
        assert "provider" in result["error"]

    def test_info_unknown_provider(self):
        """Test info endpoint with unknown provider."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_credential_fields = StanceRequestHandler._get_credential_fields.__get__(handler)
        handler._get_default_region = StanceRequestHandler._get_default_region.__get__(handler)
        handler._get_storage_types = StanceRequestHandler._get_storage_types.__get__(handler)
        handler._cloud_info = StanceRequestHandler._cloud_info.__get__(handler)

        result = handler._cloud_info({"provider": ["unknown"]})

        assert "error" in result
        assert "Unknown provider" in result["error"]

    def test_info_aws(self):
        """Test info endpoint for AWS."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_credential_fields = StanceRequestHandler._get_credential_fields.__get__(handler)
        handler._get_default_region = StanceRequestHandler._get_default_region.__get__(handler)
        handler._get_storage_types = StanceRequestHandler._get_storage_types.__get__(handler)
        handler._cloud_info = StanceRequestHandler._cloud_info.__get__(handler)

        result = handler._cloud_info({"provider": ["aws"]})

        assert result["name"] == "aws"
        assert result["display_name"] == "Amazon Web Services"
        assert "boto3" in result["packages"]
        assert "aws_access_key_id" in result["credential_fields"]
        assert result["default_region"] == "us-east-1"


class TestCloudValidateEndpoint:
    """Tests for /api/cloud/validate endpoint."""

    def test_validate_missing_provider(self):
        """Test validate endpoint without provider parameter."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._cloud_validate = StanceRequestHandler._cloud_validate.__get__(handler)

        result = handler._cloud_validate({})

        assert "error" in result
        assert "provider" in result["error"]

    def test_validate_unavailable_sdk(self):
        """Test validate endpoint when SDK is not available."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._cloud_validate = StanceRequestHandler._cloud_validate.__get__(handler)

        with mock.patch("stance.cloud.is_provider_available", return_value=False):
            result = handler._cloud_validate({"provider": ["gcp"]})

            assert result["valid"] is False
            assert "SDK not available" in result["error"]

    def test_validate_success_mock(self):
        """Test successful validation with mocked provider."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._cloud_validate = StanceRequestHandler._cloud_validate.__get__(handler)

        mock_provider = mock.MagicMock()
        mock_provider.validate_credentials.return_value = True
        mock_provider._account_id = "123456789012"

        with mock.patch("stance.cloud.is_provider_available", return_value=True):
            with mock.patch("stance.cloud.get_cloud_provider", return_value=mock_provider):
                result = handler._cloud_validate({"provider": ["aws"]})

                assert result["valid"] is True
                assert result["account_id"] == "123456789012"


class TestCloudAccountEndpoint:
    """Tests for /api/cloud/account endpoint."""

    def test_account_missing_provider(self):
        """Test account endpoint without provider parameter."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._cloud_account = StanceRequestHandler._cloud_account.__get__(handler)

        result = handler._cloud_account({})

        assert "error" in result
        assert "provider" in result["error"]


class TestCloudRegionsEndpoint:
    """Tests for /api/cloud/regions endpoint."""

    def test_regions_missing_provider(self):
        """Test regions endpoint without provider parameter."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._cloud_regions = StanceRequestHandler._cloud_regions.__get__(handler)

        result = handler._cloud_regions({})

        assert "error" in result
        assert "provider" in result["error"]


class TestCloudAvailabilityEndpoint:
    """Tests for /api/cloud/availability endpoint."""

    def test_availability(self):
        """Test availability endpoint."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._cloud_availability = StanceRequestHandler._cloud_availability.__get__(handler)

        result = handler._cloud_availability({})

        assert "availability" in result
        assert "total" in result
        assert "available_count" in result
        assert result["total"] == 3

        provider_names = [a["provider"] for a in result["availability"]]
        assert "aws" in provider_names
        assert "gcp" in provider_names
        assert "azure" in provider_names


class TestCloudPackagesEndpoint:
    """Tests for /api/cloud/packages endpoint."""

    def test_packages_all(self):
        """Test packages endpoint without filter."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._cloud_packages = StanceRequestHandler._cloud_packages.__get__(handler)

        result = handler._cloud_packages({})

        assert "packages" in result
        assert len(result["packages"]) == 3
        assert result["filter"] is None

    def test_packages_filtered(self):
        """Test packages endpoint with filter."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._cloud_packages = StanceRequestHandler._cloud_packages.__get__(handler)

        result = handler._cloud_packages({"provider": ["aws"]})

        assert len(result["packages"]) == 1
        assert result["packages"][0]["provider"] == "aws"
        assert result["filter"] == "aws"


class TestCloudCredentialsEndpoint:
    """Tests for /api/cloud/credentials endpoint."""

    def test_credentials_all(self):
        """Test credentials endpoint without filter."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_credential_fields = StanceRequestHandler._get_credential_fields.__get__(handler)
        handler._cloud_credentials = StanceRequestHandler._cloud_credentials.__get__(handler)

        result = handler._cloud_credentials({})

        assert "credentials" in result
        assert len(result["credentials"]) == 3
        assert result["filter"] is None

    def test_credentials_filtered(self):
        """Test credentials endpoint with filter."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_credential_fields = StanceRequestHandler._get_credential_fields.__get__(handler)
        handler._cloud_credentials = StanceRequestHandler._cloud_credentials.__get__(handler)

        result = handler._cloud_credentials({"provider": ["aws"]})

        assert len(result["credentials"]) == 1
        assert result["credentials"][0]["provider"] == "aws"
        assert result["filter"] == "aws"


class TestCloudExceptionsEndpoint:
    """Tests for /api/cloud/exceptions endpoint."""

    def test_exceptions(self):
        """Test exceptions endpoint."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._cloud_exceptions = StanceRequestHandler._cloud_exceptions.__get__(handler)

        result = handler._cloud_exceptions({})

        assert "exceptions" in result
        assert len(result["exceptions"]) == 5

        exception_names = [e["name"] for e in result["exceptions"]]
        assert "CloudProviderError" in exception_names
        assert "AuthenticationError" in exception_names
        assert "ConfigurationError" in exception_names


class TestCloudStatusEndpoint:
    """Tests for /api/cloud/status endpoint."""

    def test_status(self):
        """Test status endpoint."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._cloud_status = StanceRequestHandler._cloud_status.__get__(handler)

        result = handler._cloud_status({})

        assert result["module"] == "cloud"
        assert "components" in result
        assert "providers" in result
        assert "capabilities" in result

        assert "CloudProvider" in result["components"]
        assert "CloudCredentials" in result["components"]


class TestCloudSummaryEndpoint:
    """Tests for /api/cloud/summary endpoint."""

    def test_summary(self):
        """Test summary endpoint."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_cloud_provider_metadata = StanceRequestHandler._get_cloud_provider_metadata.__get__(handler)
        handler._cloud_summary = StanceRequestHandler._cloud_summary.__get__(handler)

        result = handler._cloud_summary({})

        assert "overview" in result
        assert "features" in result
        assert "architecture" in result
        assert "exception_hierarchy" in result

    def test_summary_overview(self):
        """Test summary overview section."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_cloud_provider_metadata = StanceRequestHandler._get_cloud_provider_metadata.__get__(handler)
        handler._cloud_summary = StanceRequestHandler._cloud_summary.__get__(handler)

        result = handler._cloud_summary({})

        overview = result["overview"]
        assert "description" in overview
        assert "total_providers" in overview
        assert "available_providers" in overview
        assert "providers" in overview


class TestHelperMethods:
    """Tests for helper methods."""

    def test_get_cloud_provider_metadata(self):
        """Test _get_cloud_provider_metadata method."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_cloud_provider_metadata = StanceRequestHandler._get_cloud_provider_metadata.__get__(handler)

        metadata = handler._get_cloud_provider_metadata()

        assert len(metadata) == 3

        for p in metadata:
            assert "name" in p
            assert "display_name" in p
            assert "available" in p
            assert "packages" in p
            assert "description" in p

    def test_get_credential_fields(self):
        """Test _get_credential_fields method."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_credential_fields = StanceRequestHandler._get_credential_fields.__get__(handler)

        aws_fields = handler._get_credential_fields("aws")
        assert "aws_access_key_id" in aws_fields

        gcp_fields = handler._get_credential_fields("gcp")
        assert "gcp_project_id" in gcp_fields

        azure_fields = handler._get_credential_fields("azure")
        assert "azure_subscription_id" in azure_fields

    def test_get_default_region(self):
        """Test _get_default_region method."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_default_region = StanceRequestHandler._get_default_region.__get__(handler)

        assert handler._get_default_region("aws") == "us-east-1"
        assert handler._get_default_region("gcp") == "us-central1"
        assert handler._get_default_region("azure") == "eastus"

    def test_get_storage_types(self):
        """Test _get_storage_types method."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._get_storage_types = StanceRequestHandler._get_storage_types.__get__(handler)

        aws_types = handler._get_storage_types("aws")
        assert "s3" in aws_types

        gcp_types = handler._get_storage_types("gcp")
        assert "gcs" in gcp_types

        azure_types = handler._get_storage_types("azure")
        assert "blob" in azure_types


class TestCloudApiIntegration:
    """Integration tests for cloud API endpoints."""

    def test_all_endpoints_callable(self):
        """Test all endpoints are callable."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        # Bind all methods
        handler._get_cloud_provider_metadata = StanceRequestHandler._get_cloud_provider_metadata.__get__(handler)
        handler._get_credential_fields = StanceRequestHandler._get_credential_fields.__get__(handler)
        handler._get_default_region = StanceRequestHandler._get_default_region.__get__(handler)
        handler._get_storage_types = StanceRequestHandler._get_storage_types.__get__(handler)
        handler._cloud_list = StanceRequestHandler._cloud_list.__get__(handler)
        handler._cloud_info = StanceRequestHandler._cloud_info.__get__(handler)
        handler._cloud_availability = StanceRequestHandler._cloud_availability.__get__(handler)
        handler._cloud_packages = StanceRequestHandler._cloud_packages.__get__(handler)
        handler._cloud_credentials = StanceRequestHandler._cloud_credentials.__get__(handler)
        handler._cloud_exceptions = StanceRequestHandler._cloud_exceptions.__get__(handler)
        handler._cloud_status = StanceRequestHandler._cloud_status.__get__(handler)
        handler._cloud_summary = StanceRequestHandler._cloud_summary.__get__(handler)

        # Test each endpoint
        endpoints = [
            ("_cloud_list", {}),
            ("_cloud_info", {"provider": ["aws"]}),
            ("_cloud_availability", {}),
            ("_cloud_packages", {}),
            ("_cloud_credentials", {}),
            ("_cloud_exceptions", {}),
            ("_cloud_status", {}),
            ("_cloud_summary", {}),
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
        handler._get_cloud_provider_metadata = StanceRequestHandler._get_cloud_provider_metadata.__get__(handler)
        handler._get_credential_fields = StanceRequestHandler._get_credential_fields.__get__(handler)
        handler._get_default_region = StanceRequestHandler._get_default_region.__get__(handler)
        handler._get_storage_types = StanceRequestHandler._get_storage_types.__get__(handler)
        handler._cloud_list = StanceRequestHandler._cloud_list.__get__(handler)
        handler._cloud_info = StanceRequestHandler._cloud_info.__get__(handler)
        handler._cloud_availability = StanceRequestHandler._cloud_availability.__get__(handler)
        handler._cloud_packages = StanceRequestHandler._cloud_packages.__get__(handler)
        handler._cloud_credentials = StanceRequestHandler._cloud_credentials.__get__(handler)
        handler._cloud_exceptions = StanceRequestHandler._cloud_exceptions.__get__(handler)
        handler._cloud_status = StanceRequestHandler._cloud_status.__get__(handler)
        handler._cloud_summary = StanceRequestHandler._cloud_summary.__get__(handler)

        endpoints = [
            ("_cloud_list", {}),
            ("_cloud_info", {"provider": ["aws"]}),
            ("_cloud_availability", {}),
            ("_cloud_packages", {}),
            ("_cloud_credentials", {}),
            ("_cloud_exceptions", {}),
            ("_cloud_status", {}),
            ("_cloud_summary", {}),
        ]

        for method_name, params in endpoints:
            method = getattr(handler, method_name)
            result = method(params)
            try:
                json.dumps(result)
            except (TypeError, ValueError) as e:
                pytest.fail(f"{method_name} response not JSON serializable: {e}")
