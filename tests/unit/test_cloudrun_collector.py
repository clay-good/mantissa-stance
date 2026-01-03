"""
Unit tests for GCPCloudRunCollector.

Tests cover:
- Cloud Run service collection with mocked GCP responses
- Network exposure determination (ingress settings)
- VPC connector and direct VPC configuration
- Binary authorization configuration
- Service account detection
- Container configuration and environment variables
- CMEK encryption detection
- Scaling configuration
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


class TestGCPCloudRunCollector:
    """Tests for GCPCloudRunCollector."""

    def test_cloudrun_collector_init(self):
        """Test GCPCloudRunCollector can be initialized."""
        import importlib
        import stance.collectors.gcp_cloudrun as gcp_cloudrun_module
        importlib.reload(gcp_cloudrun_module)

        collector = gcp_cloudrun_module.GCPCloudRunCollector(project_id="test-project")
        assert collector.collector_name == "gcp_cloudrun"
        assert collector.project_id == "test-project"
        assert "gcp_cloud_run_service" in collector.resource_types
        assert "gcp_cloud_run_revision" in collector.resource_types

    def test_cloudrun_collector_collect_services(self, mock_cloudrun_service):
        """Test Cloud Run service collection with mock response."""
        import importlib
        import stance.collectors.gcp_cloudrun as gcp_cloudrun_module
        importlib.reload(gcp_cloudrun_module)

        collector = gcp_cloudrun_module.GCPCloudRunCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_cloudrun_service):
            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            assert len(assets) == 1

            svc = assets[0]
            assert svc.name == "my-service"
            assert svc.resource_type == "gcp_cloud_run_service"
            assert svc.cloud_provider == "gcp"
            assert svc.account_id == "test-project"
            assert svc.region == "us-central1"

    def test_cloudrun_collector_public_ingress(self, mock_cloudrun_service_public):
        """Test service with public ingress has internet exposure."""
        import importlib
        import stance.collectors.gcp_cloudrun as gcp_cloudrun_module
        importlib.reload(gcp_cloudrun_module)

        collector = gcp_cloudrun_module.GCPCloudRunCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_cloudrun_service_public):
            assets = collector.collect()

            assert len(assets) == 1
            svc = assets[0]
            assert svc.network_exposure == NETWORK_EXPOSURE_INTERNET
            assert svc.raw_config["allows_all_traffic"] is True

    def test_cloudrun_collector_internal_only(self, mock_cloudrun_service_internal):
        """Test service with internal-only ingress has internal exposure."""
        import importlib
        import stance.collectors.gcp_cloudrun as gcp_cloudrun_module
        importlib.reload(gcp_cloudrun_module)

        collector = gcp_cloudrun_module.GCPCloudRunCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_cloudrun_service_internal):
            assets = collector.collect()

            assert len(assets) == 1
            svc = assets[0]
            assert svc.network_exposure == NETWORK_EXPOSURE_INTERNAL
            assert svc.raw_config["allows_internal_only"] is True

    def test_cloudrun_collector_internal_lb(self, mock_cloudrun_service_internal_lb):
        """Test service with internal load balancer has internet exposure."""
        import importlib
        import stance.collectors.gcp_cloudrun as gcp_cloudrun_module
        importlib.reload(gcp_cloudrun_module)

        collector = gcp_cloudrun_module.GCPCloudRunCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_cloudrun_service_internal_lb):
            assets = collector.collect()

            assert len(assets) == 1
            svc = assets[0]
            # Internal LB can be exposed via external LB
            assert svc.network_exposure == NETWORK_EXPOSURE_INTERNET
            assert svc.raw_config["allows_internal_and_gclb"] is True

    def test_cloudrun_collector_vpc_connector(self, mock_cloudrun_service_vpc):
        """Test service with VPC connector."""
        import importlib
        import stance.collectors.gcp_cloudrun as gcp_cloudrun_module
        importlib.reload(gcp_cloudrun_module)

        collector = gcp_cloudrun_module.GCPCloudRunCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_cloudrun_service_vpc):
            assets = collector.collect()

            assert len(assets) == 1
            svc = assets[0]
            assert svc.raw_config["has_vpc_connector"] is True
            assert "vpc-connector" in svc.raw_config["vpc_connector"]

    def test_cloudrun_collector_binary_authorization(self, mock_cloudrun_service_binauthz):
        """Test service with binary authorization enabled."""
        import importlib
        import stance.collectors.gcp_cloudrun as gcp_cloudrun_module
        importlib.reload(gcp_cloudrun_module)

        collector = gcp_cloudrun_module.GCPCloudRunCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_cloudrun_service_binauthz):
            assets = collector.collect()

            assert len(assets) == 1
            svc = assets[0]
            assert svc.raw_config["binary_authorization_enabled"] is True

    def test_cloudrun_collector_default_service_account(self, mock_cloudrun_service):
        """Test detection of default service account."""
        import importlib
        import stance.collectors.gcp_cloudrun as gcp_cloudrun_module
        importlib.reload(gcp_cloudrun_module)

        collector = gcp_cloudrun_module.GCPCloudRunCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_cloudrun_service):
            assets = collector.collect()

            assert len(assets) == 1
            svc = assets[0]
            assert svc.raw_config["uses_default_service_account"] is True

    def test_cloudrun_collector_custom_service_account(self, mock_cloudrun_service_custom_sa):
        """Test detection of custom service account."""
        import importlib
        import stance.collectors.gcp_cloudrun as gcp_cloudrun_module
        importlib.reload(gcp_cloudrun_module)

        collector = gcp_cloudrun_module.GCPCloudRunCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_cloudrun_service_custom_sa):
            assets = collector.collect()

            assert len(assets) == 1
            svc = assets[0]
            assert svc.raw_config["uses_default_service_account"] is False
            assert "my-sa@" in svc.raw_config["service_account"]

    def test_cloudrun_collector_cmek(self, mock_cloudrun_service_cmek):
        """Test service with customer-managed encryption key."""
        import importlib
        import stance.collectors.gcp_cloudrun as gcp_cloudrun_module
        importlib.reload(gcp_cloudrun_module)

        collector = gcp_cloudrun_module.GCPCloudRunCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_cloudrun_service_cmek):
            assets = collector.collect()

            assert len(assets) == 1
            svc = assets[0]
            assert svc.raw_config["has_cmek"] is True
            assert "projects/test-project/locations/us-central1/keyRings" in svc.raw_config["encryption_key"]

    def test_cloudrun_collector_scaling(self, mock_cloudrun_service_scaling):
        """Test service scaling configuration extraction."""
        import importlib
        import stance.collectors.gcp_cloudrun as gcp_cloudrun_module
        importlib.reload(gcp_cloudrun_module)

        collector = gcp_cloudrun_module.GCPCloudRunCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_cloudrun_service_scaling):
            assets = collector.collect()

            assert len(assets) == 1
            svc = assets[0]
            assert svc.raw_config["min_instance_count"] == 1
            assert svc.raw_config["max_instance_count"] == 10

    def test_cloudrun_collector_secrets(self, mock_cloudrun_service_secrets):
        """Test service with secrets from Secret Manager."""
        import importlib
        import stance.collectors.gcp_cloudrun as gcp_cloudrun_module
        importlib.reload(gcp_cloudrun_module)

        collector = gcp_cloudrun_module.GCPCloudRunCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_cloudrun_service_secrets):
            assets = collector.collect()

            assert len(assets) == 1
            svc = assets[0]
            assert svc.raw_config["has_secrets"] is True

    def test_cloudrun_collector_handles_empty_response(self, mock_cloudrun_service_empty):
        """Test handling of empty service list."""
        import importlib
        import stance.collectors.gcp_cloudrun as gcp_cloudrun_module
        importlib.reload(gcp_cloudrun_module)

        collector = gcp_cloudrun_module.GCPCloudRunCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_cloudrun_service_empty):
            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            assert len(assets) == 0

    def test_cloudrun_collector_handles_api_error(self, mock_cloudrun_service_error):
        """Test graceful handling of API errors."""
        import importlib
        import stance.collectors.gcp_cloudrun as gcp_cloudrun_module
        importlib.reload(gcp_cloudrun_module)

        collector = gcp_cloudrun_module.GCPCloudRunCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_cloudrun_service_error):
            # Should not raise, but return empty collection
            assets = collector.collect()
            assert isinstance(assets, AssetCollection)
            assert len(assets) == 0

    def test_cloudrun_collector_labels_as_tags(self, mock_cloudrun_service):
        """Test that labels are extracted as tags."""
        import importlib
        import stance.collectors.gcp_cloudrun as gcp_cloudrun_module
        importlib.reload(gcp_cloudrun_module)

        collector = gcp_cloudrun_module.GCPCloudRunCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_cloudrun_service):
            assets = collector.collect()

            assert len(assets) == 1
            svc = assets[0]
            assert svc.tags == {"environment": "production", "team": "platform"}


# Helper to create a mock service that handles pagination
def _create_mock_service(services_list):
    """Create a mock Cloud Run API service."""
    service = MagicMock()

    mock_list_request = MagicMock()
    mock_list_request.execute.return_value = {"services": services_list}

    mock_services = MagicMock()
    mock_services.list.return_value = mock_list_request
    # list_next must return None to stop pagination
    mock_services.list_next.return_value = None

    mock_locations = MagicMock()
    mock_locations.services.return_value = mock_services

    mock_projects = MagicMock()
    mock_projects.locations.return_value = mock_locations

    service.projects.return_value = mock_projects
    return service


# Fixtures for GCP Cloud Run tests

@pytest.fixture
def mock_cloudrun_service():
    """Return a mocked Cloud Run API service with sample responses."""
    services = [
        {
            "name": "projects/test-project/locations/us-central1/services/my-service",
            "uri": "https://my-service-xyz-uc.a.run.app",
            "ingress": "INGRESS_TRAFFIC_ALL",
            "launchStage": "GA",
            "template": {
                "serviceAccount": "123456-compute@developer.gserviceaccount.com",
                "scaling": {
                    "minInstanceCount": 0,
                    "maxInstanceCount": 100,
                },
                "containers": [
                    {
                        "image": "gcr.io/test-project/my-image:latest",
                        "ports": [{"containerPort": 8080}],
                        "resources": {"limits": {"cpu": "1", "memory": "512Mi"}},
                        "env": [{"name": "LOG_LEVEL", "value": "INFO"}],
                    }
                ],
            },
            "traffic": [{"type": "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST", "percent": 100}],
            "labels": {
                "environment": "production",
                "team": "platform",
            },
            "conditions": [{"type": "Ready", "state": "CONDITION_SUCCEEDED"}],
            "createTime": "2024-01-01T00:00:00.000Z",
            "updateTime": "2024-01-15T00:00:00.000Z",
        }
    ]
    return _create_mock_service(services)


@pytest.fixture
def mock_cloudrun_service_public():
    """Return a mocked service for a public Cloud Run service."""
    services = [
        {
            "name": "projects/test-project/locations/us-central1/services/public-service",
            "uri": "https://public-service-xyz-uc.a.run.app",
            "ingress": "INGRESS_TRAFFIC_ALL",
            "template": {
                "serviceAccount": "my-sa@test-project.iam.gserviceaccount.com",
                "containers": [
                    {
                        "image": "gcr.io/test-project/my-image:latest",
                        "ports": [{"containerPort": 8080}],
                    }
                ],
            },
            "labels": {},
            "conditions": [{"type": "Ready", "state": "CONDITION_SUCCEEDED"}],
            "createTime": "2024-01-01T00:00:00.000Z",
        }
    ]
    return _create_mock_service(services)


@pytest.fixture
def mock_cloudrun_service_internal():
    """Return a mocked service for an internal-only Cloud Run service."""
    services = [
        {
            "name": "projects/test-project/locations/us-central1/services/internal-service",
            "uri": "https://internal-service-xyz-uc.a.run.app",
            "ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY",
            "template": {
                "serviceAccount": "my-sa@test-project.iam.gserviceaccount.com",
                "containers": [
                    {
                        "image": "gcr.io/test-project/my-image:latest",
                        "ports": [{"containerPort": 8080}],
                    }
                ],
            },
            "labels": {},
            "conditions": [{"type": "Ready", "state": "CONDITION_SUCCEEDED"}],
            "createTime": "2024-01-01T00:00:00.000Z",
        }
    ]
    return _create_mock_service(services)


@pytest.fixture
def mock_cloudrun_service_internal_lb():
    """Return a mocked service for a Cloud Run service with internal load balancer."""
    services = [
        {
            "name": "projects/test-project/locations/us-central1/services/internal-lb-service",
            "uri": "https://internal-lb-service-xyz-uc.a.run.app",
            "ingress": "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER",
            "template": {
                "serviceAccount": "my-sa@test-project.iam.gserviceaccount.com",
                "containers": [
                    {
                        "image": "gcr.io/test-project/my-image:latest",
                        "ports": [{"containerPort": 8080}],
                    }
                ],
            },
            "labels": {},
            "conditions": [{"type": "Ready", "state": "CONDITION_SUCCEEDED"}],
            "createTime": "2024-01-01T00:00:00.000Z",
        }
    ]
    return _create_mock_service(services)


@pytest.fixture
def mock_cloudrun_service_vpc():
    """Return a mocked service for a Cloud Run service with VPC connector."""
    services = [
        {
            "name": "projects/test-project/locations/us-central1/services/vpc-service",
            "uri": "https://vpc-service-xyz-uc.a.run.app",
            "ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY",
            "template": {
                "serviceAccount": "my-sa@test-project.iam.gserviceaccount.com",
                "vpcAccess": {
                    "connector": "projects/test-project/locations/us-central1/connectors/vpc-connector",
                    "egress": "ALL_TRAFFIC",
                },
                "containers": [
                    {
                        "image": "gcr.io/test-project/my-image:latest",
                        "ports": [{"containerPort": 8080}],
                    }
                ],
            },
            "labels": {},
            "conditions": [{"type": "Ready", "state": "CONDITION_SUCCEEDED"}],
            "createTime": "2024-01-01T00:00:00.000Z",
        }
    ]
    return _create_mock_service(services)


@pytest.fixture
def mock_cloudrun_service_binauthz():
    """Return a mocked service for a Cloud Run service with binary authorization."""
    services = [
        {
            "name": "projects/test-project/locations/us-central1/services/binauthz-service",
            "uri": "https://binauthz-service-xyz-uc.a.run.app",
            "ingress": "INGRESS_TRAFFIC_ALL",
            "binaryAuthorization": {
                "useDefault": True,
            },
            "template": {
                "serviceAccount": "my-sa@test-project.iam.gserviceaccount.com",
                "containers": [
                    {
                        "image": "gcr.io/test-project/my-image:latest",
                        "ports": [{"containerPort": 8080}],
                    }
                ],
            },
            "labels": {},
            "conditions": [{"type": "Ready", "state": "CONDITION_SUCCEEDED"}],
            "createTime": "2024-01-01T00:00:00.000Z",
        }
    ]
    return _create_mock_service(services)


@pytest.fixture
def mock_cloudrun_service_custom_sa():
    """Return a mocked service with a custom service account."""
    services = [
        {
            "name": "projects/test-project/locations/us-central1/services/custom-sa-service",
            "uri": "https://custom-sa-service-xyz-uc.a.run.app",
            "ingress": "INGRESS_TRAFFIC_ALL",
            "template": {
                "serviceAccount": "my-sa@test-project.iam.gserviceaccount.com",
                "containers": [
                    {
                        "image": "gcr.io/test-project/my-image:latest",
                        "ports": [{"containerPort": 8080}],
                    }
                ],
            },
            "labels": {},
            "conditions": [{"type": "Ready", "state": "CONDITION_SUCCEEDED"}],
            "createTime": "2024-01-01T00:00:00.000Z",
        }
    ]
    return _create_mock_service(services)


@pytest.fixture
def mock_cloudrun_service_cmek():
    """Return a mocked service with customer-managed encryption key."""
    services = [
        {
            "name": "projects/test-project/locations/us-central1/services/cmek-service",
            "uri": "https://cmek-service-xyz-uc.a.run.app",
            "ingress": "INGRESS_TRAFFIC_ALL",
            "template": {
                "serviceAccount": "my-sa@test-project.iam.gserviceaccount.com",
                "encryptionKey": "projects/test-project/locations/us-central1/keyRings/my-keyring/cryptoKeys/my-key",
                "containers": [
                    {
                        "image": "gcr.io/test-project/my-image:latest",
                        "ports": [{"containerPort": 8080}],
                    }
                ],
            },
            "labels": {},
            "conditions": [{"type": "Ready", "state": "CONDITION_SUCCEEDED"}],
            "createTime": "2024-01-01T00:00:00.000Z",
        }
    ]
    return _create_mock_service(services)


@pytest.fixture
def mock_cloudrun_service_scaling():
    """Return a mocked service with specific scaling configuration."""
    services = [
        {
            "name": "projects/test-project/locations/us-central1/services/scaling-service",
            "uri": "https://scaling-service-xyz-uc.a.run.app",
            "ingress": "INGRESS_TRAFFIC_ALL",
            "template": {
                "serviceAccount": "my-sa@test-project.iam.gserviceaccount.com",
                "scaling": {
                    "minInstanceCount": 1,
                    "maxInstanceCount": 10,
                },
                "containers": [
                    {
                        "image": "gcr.io/test-project/my-image:latest",
                        "ports": [{"containerPort": 8080}],
                    }
                ],
            },
            "labels": {},
            "conditions": [{"type": "Ready", "state": "CONDITION_SUCCEEDED"}],
            "createTime": "2024-01-01T00:00:00.000Z",
        }
    ]
    return _create_mock_service(services)


@pytest.fixture
def mock_cloudrun_service_secrets():
    """Return a mocked service with secrets from Secret Manager."""
    services = [
        {
            "name": "projects/test-project/locations/us-central1/services/secrets-service",
            "uri": "https://secrets-service-xyz-uc.a.run.app",
            "ingress": "INGRESS_TRAFFIC_ALL",
            "template": {
                "serviceAccount": "my-sa@test-project.iam.gserviceaccount.com",
                "containers": [
                    {
                        "image": "gcr.io/test-project/my-image:latest",
                        "ports": [{"containerPort": 8080}],
                        "env": [
                            {
                                "name": "API_KEY",
                                "valueSource": {
                                    "secretKeyRef": {
                                        "secret": "projects/test-project/secrets/api-key",
                                        "version": "latest",
                                    }
                                },
                            }
                        ],
                    }
                ],
            },
            "labels": {},
            "conditions": [{"type": "Ready", "state": "CONDITION_SUCCEEDED"}],
            "createTime": "2024-01-01T00:00:00.000Z",
        }
    ]
    return _create_mock_service(services)


@pytest.fixture
def mock_cloudrun_service_empty():
    """Return a mocked service with no services."""
    return _create_mock_service([])


@pytest.fixture
def mock_cloudrun_service_error():
    """Return a mocked service that raises an error."""
    service = MagicMock()

    mock_list = MagicMock()
    mock_list.execute.side_effect = Exception("API Error: Access Denied")

    mock_services = MagicMock()
    mock_services.list.return_value = mock_list

    mock_locations = MagicMock()
    mock_locations.services.return_value = mock_services

    mock_projects = MagicMock()
    mock_projects.locations.return_value = mock_locations

    service.projects.return_value = mock_projects
    return service
