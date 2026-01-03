"""
Unit tests for GCPCloudFunctionsCollector.

Tests cover:
- Cloud Functions v1 (1st gen) collection with mocked GCP responses
- Cloud Functions v2 (2nd gen) collection
- Network exposure determination (HTTPS triggers, ingress settings)
- Deprecated runtime detection
- VPC connector configuration
- Service account detection
- Environment variables and secrets handling
- Error handling for API failures
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from stance.models import (
    AssetCollection,
    NETWORK_EXPOSURE_INTERNET,
    NETWORK_EXPOSURE_INTERNAL,
    NETWORK_EXPOSURE_ISOLATED,
)


# Mock the GCP dependencies at module level before importing the collector
mock_googleapiclient = MagicMock()
mock_discovery = MagicMock()
mock_google_auth = MagicMock()
mock_google_oauth2 = MagicMock()
mock_service_account = MagicMock()

sys.modules["googleapiclient"] = mock_googleapiclient
sys.modules["googleapiclient.discovery"] = mock_discovery
sys.modules["google"] = MagicMock()
sys.modules["google.auth"] = mock_google_auth
sys.modules["google.oauth2"] = mock_google_oauth2
sys.modules["google.oauth2.service_account"] = mock_service_account


class TestGCPCloudFunctionsCollector:
    """Tests for GCPCloudFunctionsCollector."""

    def test_gcp_functions_collector_init(self):
        """Test GCPCloudFunctionsCollector can be initialized."""
        import importlib
        import stance.collectors.gcp_functions as gcp_functions_module
        importlib.reload(gcp_functions_module)

        collector = gcp_functions_module.GCPCloudFunctionsCollector(project_id="test-project")
        assert collector.collector_name == "gcp_functions"
        assert collector.project_id == "test-project"
        assert "gcp_cloud_function" in collector.resource_types

    def test_gcp_functions_collector_collect_v1(self, mock_gcp_functions_service_v1):
        """Test 1st gen Cloud Functions collection with mock response."""
        import importlib
        import stance.collectors.gcp_functions as gcp_functions_module
        importlib.reload(gcp_functions_module)

        collector = gcp_functions_module.GCPCloudFunctionsCollector(project_id="test-project")

        with patch.object(collector, "_get_service_v1", return_value=mock_gcp_functions_service_v1):
            with patch.object(collector, "_get_service_v2", return_value=_create_empty_mock_service()):
                assets = collector.collect()

                assert isinstance(assets, AssetCollection)
                assert len(assets) == 1

                func = assets[0]
                assert func.name == "my-function"
                assert func.resource_type == "gcp_cloud_function"
                assert func.cloud_provider == "gcp"
                assert func.account_id == "test-project"
                assert func.region == "us-central1"
                assert func.raw_config["generation"] == "1st"

    def test_gcp_functions_collector_collect_v2(self, mock_gcp_functions_service_v2):
        """Test 2nd gen Cloud Functions collection with mock response."""
        import importlib
        import stance.collectors.gcp_functions as gcp_functions_module
        importlib.reload(gcp_functions_module)

        collector = gcp_functions_module.GCPCloudFunctionsCollector(project_id="test-project")

        with patch.object(collector, "_get_service_v1", return_value=_create_empty_mock_service()):
            with patch.object(collector, "_get_service_v2", return_value=mock_gcp_functions_service_v2):
                assets = collector.collect()

                assert isinstance(assets, AssetCollection)
                assert len(assets) == 1

                func = assets[0]
                assert func.name == "my-function-v2"
                assert func.resource_type == "gcp_cloud_function"
                assert func.raw_config["generation"] == "2nd"

    def test_gcp_functions_collector_https_trigger_public(self, mock_gcp_functions_service_v1_public):
        """Test function with public HTTPS trigger has internet exposure."""
        import importlib
        import stance.collectors.gcp_functions as gcp_functions_module
        importlib.reload(gcp_functions_module)

        collector = gcp_functions_module.GCPCloudFunctionsCollector(project_id="test-project")

        with patch.object(collector, "_get_service_v1", return_value=mock_gcp_functions_service_v1_public):
            with patch.object(collector, "_get_service_v2", return_value=_create_empty_mock_service()):
                assets = collector.collect()

                assert len(assets) == 1
                func = assets[0]
                assert func.network_exposure == NETWORK_EXPOSURE_INTERNET
                assert func.raw_config["allows_all_traffic"] is True

    def test_gcp_functions_collector_internal_only(self, mock_gcp_functions_service_v1_internal):
        """Test function with internal-only ingress has internal exposure."""
        import importlib
        import stance.collectors.gcp_functions as gcp_functions_module
        importlib.reload(gcp_functions_module)

        collector = gcp_functions_module.GCPCloudFunctionsCollector(project_id="test-project")

        with patch.object(collector, "_get_service_v1", return_value=mock_gcp_functions_service_v1_internal):
            with patch.object(collector, "_get_service_v2", return_value=_create_empty_mock_service()):
                assets = collector.collect()

                assert len(assets) == 1
                func = assets[0]
                assert func.network_exposure == NETWORK_EXPOSURE_INTERNAL
                assert func.raw_config["allows_internal_only"] is True

    def test_gcp_functions_collector_event_triggered_isolated(self, mock_gcp_functions_service_v1_event):
        """Test event-triggered function without VPC has isolated exposure."""
        import importlib
        import stance.collectors.gcp_functions as gcp_functions_module
        importlib.reload(gcp_functions_module)

        collector = gcp_functions_module.GCPCloudFunctionsCollector(project_id="test-project")

        with patch.object(collector, "_get_service_v1", return_value=mock_gcp_functions_service_v1_event):
            with patch.object(collector, "_get_service_v2", return_value=_create_empty_mock_service()):
                assets = collector.collect()

                assert len(assets) == 1
                func = assets[0]
                assert func.network_exposure == NETWORK_EXPOSURE_ISOLATED
                assert func.raw_config["has_https_trigger"] is False
                assert func.raw_config["has_event_trigger"] is True

    def test_gcp_functions_collector_deprecated_runtime(self, mock_gcp_functions_service_v1_deprecated):
        """Test detection of deprecated runtime."""
        import importlib
        import stance.collectors.gcp_functions as gcp_functions_module
        importlib.reload(gcp_functions_module)

        collector = gcp_functions_module.GCPCloudFunctionsCollector(project_id="test-project")

        with patch.object(collector, "_get_service_v1", return_value=mock_gcp_functions_service_v1_deprecated):
            with patch.object(collector, "_get_service_v2", return_value=_create_empty_mock_service()):
                assets = collector.collect()

                assert len(assets) == 1
                func = assets[0]
                assert func.raw_config["runtime"] == "python37"
                assert func.raw_config["runtime_deprecated"] is True

    def test_gcp_functions_collector_vpc_connector(self, mock_gcp_functions_service_v1_vpc):
        """Test function with VPC connector."""
        import importlib
        import stance.collectors.gcp_functions as gcp_functions_module
        importlib.reload(gcp_functions_module)

        collector = gcp_functions_module.GCPCloudFunctionsCollector(project_id="test-project")

        with patch.object(collector, "_get_service_v1", return_value=mock_gcp_functions_service_v1_vpc):
            with patch.object(collector, "_get_service_v2", return_value=_create_empty_mock_service()):
                assets = collector.collect()

                assert len(assets) == 1
                func = assets[0]
                assert func.raw_config["has_vpc_connector"] is True
                assert "vpc-connector" in func.raw_config["vpc_connector"]

    def test_gcp_functions_collector_default_service_account(self, mock_gcp_functions_service_v1):
        """Test detection of default service account."""
        import importlib
        import stance.collectors.gcp_functions as gcp_functions_module
        importlib.reload(gcp_functions_module)

        collector = gcp_functions_module.GCPCloudFunctionsCollector(project_id="test-project")

        with patch.object(collector, "_get_service_v1", return_value=mock_gcp_functions_service_v1):
            with patch.object(collector, "_get_service_v2", return_value=_create_empty_mock_service()):
                assets = collector.collect()

                assert len(assets) == 1
                func = assets[0]
                assert func.raw_config["uses_default_service_account"] is True

    def test_gcp_functions_collector_secrets(self, mock_gcp_functions_service_v1_secrets):
        """Test extraction of secret references."""
        import importlib
        import stance.collectors.gcp_functions as gcp_functions_module
        importlib.reload(gcp_functions_module)

        collector = gcp_functions_module.GCPCloudFunctionsCollector(project_id="test-project")

        with patch.object(collector, "_get_service_v1", return_value=mock_gcp_functions_service_v1_secrets):
            with patch.object(collector, "_get_service_v2", return_value=_create_empty_mock_service()):
                assets = collector.collect()

                assert len(assets) == 1
                func = assets[0]
                assert func.raw_config["has_secrets"] is True
                assert len(func.raw_config["secret_references"]) == 1

    def test_gcp_functions_collector_handles_empty_response(self, mock_gcp_functions_service_empty):
        """Test handling of empty function list."""
        import importlib
        import stance.collectors.gcp_functions as gcp_functions_module
        importlib.reload(gcp_functions_module)

        collector = gcp_functions_module.GCPCloudFunctionsCollector(project_id="test-project")

        with patch.object(collector, "_get_service_v1", return_value=mock_gcp_functions_service_empty):
            with patch.object(collector, "_get_service_v2", return_value=mock_gcp_functions_service_empty):
                assets = collector.collect()

                assert isinstance(assets, AssetCollection)
                assert len(assets) == 0

    def test_gcp_functions_collector_handles_api_error(self, mock_gcp_functions_service_error):
        """Test graceful handling of API errors."""
        import importlib
        import stance.collectors.gcp_functions as gcp_functions_module
        importlib.reload(gcp_functions_module)

        collector = gcp_functions_module.GCPCloudFunctionsCollector(project_id="test-project")

        with patch.object(collector, "_get_service_v1", return_value=mock_gcp_functions_service_error):
            with patch.object(collector, "_get_service_v2", return_value=mock_gcp_functions_service_error):
                # Should not raise, but return empty collection
                assets = collector.collect()
                assert isinstance(assets, AssetCollection)
                assert len(assets) == 0

    def test_gcp_functions_collector_labels_as_tags(self, mock_gcp_functions_service_v1):
        """Test that labels are extracted as tags."""
        import importlib
        import stance.collectors.gcp_functions as gcp_functions_module
        importlib.reload(gcp_functions_module)

        collector = gcp_functions_module.GCPCloudFunctionsCollector(project_id="test-project")

        with patch.object(collector, "_get_service_v1", return_value=mock_gcp_functions_service_v1):
            with patch.object(collector, "_get_service_v2", return_value=_create_empty_mock_service()):
                assets = collector.collect()

                assert len(assets) == 1
                func = assets[0]
                assert func.tags == {"environment": "production", "team": "platform"}


# Helper to create a mock service that handles pagination
def _create_mock_service(functions_list):
    """Create a mock Cloud Functions API service."""
    service = MagicMock()

    mock_list_request = MagicMock()
    mock_list_request.execute.return_value = {"functions": functions_list}

    mock_functions = MagicMock()
    mock_functions.list.return_value = mock_list_request
    # list_next must return None to stop pagination
    mock_functions.list_next.return_value = None

    mock_locations = MagicMock()
    mock_locations.functions.return_value = mock_functions

    mock_projects = MagicMock()
    mock_projects.locations.return_value = mock_locations

    service.projects.return_value = mock_projects
    return service


def _create_empty_mock_service():
    """Create an empty mock service for when we only want to test one version."""
    return _create_mock_service([])


# Fixtures for GCP Cloud Functions tests

@pytest.fixture
def mock_gcp_functions_service_v1():
    """Return a mocked Cloud Functions v1 API service with sample responses."""
    functions = [
        {
            "name": "projects/test-project/locations/us-central1/functions/my-function",
            "runtime": "python311",
            "status": "ACTIVE",
            "entryPoint": "main",
            "httpsTrigger": {
                "url": "https://us-central1-test-project.cloudfunctions.net/my-function",
                "securityLevel": "SECURE_ALWAYS",
            },
            "ingressSettings": "ALLOW_ALL",
            "serviceAccountEmail": "test-project@appspot.gserviceaccount.com",
            "labels": {
                "environment": "production",
                "team": "platform",
            },
            "environmentVariables": {
                "LOG_LEVEL": "INFO",
            },
            "availableMemoryMb": 256,
            "timeout": "60s",
            "updateTime": "2024-01-01T00:00:00.000Z",
        }
    ]
    return _create_mock_service(functions)


@pytest.fixture
def mock_gcp_functions_service_v2():
    """Return a mocked Cloud Functions v2 API service with sample responses."""
    functions = [
        {
            "name": "projects/test-project/locations/us-central1/functions/my-function-v2",
            "state": "ACTIVE",
            "environment": "GEN_2",
            "buildConfig": {
                "runtime": "python311",
                "entryPoint": "main",
            },
            "serviceConfig": {
                "uri": "https://my-function-v2-xyz-uc.a.run.app",
                "serviceAccountEmail": "my-sa@test-project.iam.gserviceaccount.com",
                "ingressSettings": "ALLOW_ALL",
                "environmentVariables": {"LOG_LEVEL": "INFO"},
                "availableMemory": "256M",
                "timeoutSeconds": 60,
            },
            "labels": {"environment": "staging"},
            "createTime": "2024-01-01T00:00:00.000Z",
            "updateTime": "2024-01-15T00:00:00.000Z",
        }
    ]
    return _create_mock_service(functions)


@pytest.fixture
def mock_gcp_functions_service_v1_public():
    """Return a mocked service for a public HTTPS function."""
    functions = [
        {
            "name": "projects/test-project/locations/us-central1/functions/public-function",
            "runtime": "nodejs18",
            "status": "ACTIVE",
            "httpsTrigger": {
                "url": "https://us-central1-test-project.cloudfunctions.net/public-function",
            },
            "ingressSettings": "ALLOW_ALL",
            "serviceAccountEmail": "my-sa@test-project.iam.gserviceaccount.com",
            "labels": {},
        }
    ]
    return _create_mock_service(functions)


@pytest.fixture
def mock_gcp_functions_service_v1_internal():
    """Return a mocked service for an internal-only function."""
    functions = [
        {
            "name": "projects/test-project/locations/us-central1/functions/internal-function",
            "runtime": "python311",
            "status": "ACTIVE",
            "httpsTrigger": {
                "url": "https://us-central1-test-project.cloudfunctions.net/internal-function",
            },
            "ingressSettings": "ALLOW_INTERNAL_ONLY",
            "serviceAccountEmail": "my-sa@test-project.iam.gserviceaccount.com",
            "labels": {},
        }
    ]
    return _create_mock_service(functions)


@pytest.fixture
def mock_gcp_functions_service_v1_event():
    """Return a mocked service for an event-triggered function."""
    functions = [
        {
            "name": "projects/test-project/locations/us-central1/functions/event-function",
            "runtime": "python311",
            "status": "ACTIVE",
            "eventTrigger": {
                "eventType": "google.storage.object.finalize",
                "resource": "projects/test-project/buckets/my-bucket",
            },
            "serviceAccountEmail": "my-sa@test-project.iam.gserviceaccount.com",
            "labels": {},
        }
    ]
    return _create_mock_service(functions)


@pytest.fixture
def mock_gcp_functions_service_v1_deprecated():
    """Return a mocked service for a function with deprecated runtime."""
    functions = [
        {
            "name": "projects/test-project/locations/us-central1/functions/deprecated-function",
            "runtime": "python37",
            "status": "ACTIVE",
            "httpsTrigger": {
                "url": "https://us-central1-test-project.cloudfunctions.net/deprecated-function",
            },
            "ingressSettings": "ALLOW_ALL",
            "serviceAccountEmail": "my-sa@test-project.iam.gserviceaccount.com",
            "labels": {},
        }
    ]
    return _create_mock_service(functions)


@pytest.fixture
def mock_gcp_functions_service_v1_vpc():
    """Return a mocked service for a function with VPC connector."""
    functions = [
        {
            "name": "projects/test-project/locations/us-central1/functions/vpc-function",
            "runtime": "python311",
            "status": "ACTIVE",
            "eventTrigger": {
                "eventType": "google.pubsub.topic.publish",
                "resource": "projects/test-project/topics/my-topic",
            },
            "vpcConnector": "projects/test-project/locations/us-central1/connectors/vpc-connector",
            "vpcConnectorEgressSettings": "ALL_TRAFFIC",
            "serviceAccountEmail": "my-sa@test-project.iam.gserviceaccount.com",
            "labels": {},
        }
    ]
    return _create_mock_service(functions)


@pytest.fixture
def mock_gcp_functions_service_v1_secrets():
    """Return a mocked service for a function with secrets."""
    functions = [
        {
            "name": "projects/test-project/locations/us-central1/functions/secrets-function",
            "runtime": "python311",
            "status": "ACTIVE",
            "httpsTrigger": {
                "url": "https://us-central1-test-project.cloudfunctions.net/secrets-function",
            },
            "ingressSettings": "ALLOW_ALL",
            "serviceAccountEmail": "my-sa@test-project.iam.gserviceaccount.com",
            "secretEnvironmentVariables": [
                {
                    "key": "API_KEY",
                    "secret": "projects/test-project/secrets/api-key",
                    "version": "latest",
                }
            ],
            "labels": {},
        }
    ]
    return _create_mock_service(functions)


@pytest.fixture
def mock_gcp_functions_service_empty():
    """Return a mocked service with no functions."""
    return _create_mock_service([])


@pytest.fixture
def mock_gcp_functions_service_error():
    """Return a mocked service that raises an error."""
    service = MagicMock()

    mock_list = MagicMock()
    mock_list.execute.side_effect = Exception("API Error: Access Denied")

    mock_functions = MagicMock()
    mock_functions.list.return_value = mock_list

    mock_locations = MagicMock()
    mock_locations.functions.return_value = mock_functions

    mock_projects = MagicMock()
    mock_projects.locations.return_value = mock_locations

    service.projects.return_value = mock_projects
    return service
