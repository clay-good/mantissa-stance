"""
Unit tests for GCPCloudSQLCollector.

Tests cover:
- Cloud SQL instance collection with mocked GCP responses
- Network exposure determination (public IP, authorized networks)
- SSL/TLS configuration checking
- CMEK encryption detection
- Backup configuration collection
- Database flags extraction
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


class TestGCPCloudSQLCollector:
    """Tests for GCPCloudSQLCollector."""

    def test_gcp_sql_collector_init(self):
        """Test GCPCloudSQLCollector can be initialized."""
        # Need to reload module after mocking
        import importlib
        import stance.collectors.gcp_sql as gcp_sql_module
        importlib.reload(gcp_sql_module)

        collector = gcp_sql_module.GCPCloudSQLCollector(project_id="test-project")
        assert collector.collector_name == "gcp_sql"
        assert collector.project_id == "test-project"
        assert "gcp_sql_instance" in collector.resource_types

    def test_gcp_sql_collector_collect_instances(self, mock_gcp_sql_service):
        """Test Cloud SQL instance collection with mock response."""
        import importlib
        import stance.collectors.gcp_sql as gcp_sql_module
        importlib.reload(gcp_sql_module)

        collector = gcp_sql_module.GCPCloudSQLCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_gcp_sql_service):
            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            assert len(assets) == 1

            instance = assets[0]
            assert instance.name == "production-db"
            assert instance.resource_type == "gcp_sql_instance"
            assert instance.cloud_provider == "gcp"
            assert instance.account_id == "test-project"
            assert instance.region == "us-central1"

    def test_gcp_sql_collector_private_instance(self, mock_gcp_sql_service_private):
        """Test collection of private Cloud SQL instance."""
        import importlib
        import stance.collectors.gcp_sql as gcp_sql_module
        importlib.reload(gcp_sql_module)

        collector = gcp_sql_module.GCPCloudSQLCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_gcp_sql_service_private):
            assets = collector.collect()

            assert len(assets) == 1
            instance = assets[0]
            assert instance.network_exposure == NETWORK_EXPOSURE_INTERNAL
            assert instance.raw_config["has_private_network"] is True
            assert instance.raw_config["has_public_ip"] is False

    def test_gcp_sql_collector_public_instance_with_any_ip(self, mock_gcp_sql_service_public):
        """Test collection of public Cloud SQL instance allowing 0.0.0.0/0."""
        import importlib
        import stance.collectors.gcp_sql as gcp_sql_module
        importlib.reload(gcp_sql_module)

        collector = gcp_sql_module.GCPCloudSQLCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_gcp_sql_service_public):
            assets = collector.collect()

            assert len(assets) == 1
            instance = assets[0]
            assert instance.network_exposure == NETWORK_EXPOSURE_INTERNET
            assert instance.raw_config["allows_any_ip"] is True
            assert instance.raw_config["has_public_ip"] is True

    def test_gcp_sql_collector_cmek_encryption(self, mock_gcp_sql_service_cmek):
        """Test detection of CMEK encryption configuration."""
        import importlib
        import stance.collectors.gcp_sql as gcp_sql_module
        importlib.reload(gcp_sql_module)

        collector = gcp_sql_module.GCPCloudSQLCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_gcp_sql_service_cmek):
            assets = collector.collect()

            assert len(assets) == 1
            instance = assets[0]
            assert instance.raw_config["uses_cmek"] is True
            assert "projects/test-project/locations/us-central1/keyRings" in instance.raw_config["disk_encryption_key_name"]

    def test_gcp_sql_collector_ssl_configuration(self, mock_gcp_sql_service):
        """Test SSL configuration extraction."""
        import importlib
        import stance.collectors.gcp_sql as gcp_sql_module
        importlib.reload(gcp_sql_module)

        collector = gcp_sql_module.GCPCloudSQLCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_gcp_sql_service):
            assets = collector.collect()

            assert len(assets) == 1
            instance = assets[0]
            assert instance.raw_config["require_ssl"] is True

    def test_gcp_sql_collector_backup_configuration(self, mock_gcp_sql_service):
        """Test backup configuration extraction."""
        import importlib
        import stance.collectors.gcp_sql as gcp_sql_module
        importlib.reload(gcp_sql_module)

        collector = gcp_sql_module.GCPCloudSQLCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_gcp_sql_service):
            assets = collector.collect()

            assert len(assets) == 1
            instance = assets[0]
            assert instance.raw_config["backup_enabled"] is True
            assert instance.raw_config["point_in_time_recovery_enabled"] is True

    def test_gcp_sql_collector_database_flags(self, mock_gcp_sql_service):
        """Test database flags extraction."""
        import importlib
        import stance.collectors.gcp_sql as gcp_sql_module
        importlib.reload(gcp_sql_module)

        collector = gcp_sql_module.GCPCloudSQLCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_gcp_sql_service):
            assets = collector.collect()

            assert len(assets) == 1
            instance = assets[0]
            assert instance.raw_config["log_connections"] == "on"
            assert instance.raw_config["log_disconnections"] == "on"

    def test_gcp_sql_collector_handles_empty_response(self, mock_gcp_sql_service_empty):
        """Test handling of empty instance list."""
        import importlib
        import stance.collectors.gcp_sql as gcp_sql_module
        importlib.reload(gcp_sql_module)

        collector = gcp_sql_module.GCPCloudSQLCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_gcp_sql_service_empty):
            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            assert len(assets) == 0

    def test_gcp_sql_collector_handles_api_error(self, mock_gcp_sql_service_error):
        """Test graceful handling of API errors."""
        import importlib
        import stance.collectors.gcp_sql as gcp_sql_module
        importlib.reload(gcp_sql_module)

        collector = gcp_sql_module.GCPCloudSQLCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_gcp_sql_service_error):
            # Should not raise, but return empty collection
            assets = collector.collect()
            assert isinstance(assets, AssetCollection)
            assert len(assets) == 0

    def test_gcp_sql_collector_labels_as_tags(self, mock_gcp_sql_service):
        """Test that user labels are extracted as tags."""
        import importlib
        import stance.collectors.gcp_sql as gcp_sql_module
        importlib.reload(gcp_sql_module)

        collector = gcp_sql_module.GCPCloudSQLCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_gcp_sql_service):
            assets = collector.collect()

            assert len(assets) == 1
            instance = assets[0]
            assert instance.tags == {"environment": "production", "team": "platform"}

    def test_gcp_sql_collector_isolated_exposure(self, mock_gcp_sql_service_isolated):
        """Test Cloud SQL instance with isolated network exposure."""
        import importlib
        import stance.collectors.gcp_sql as gcp_sql_module
        importlib.reload(gcp_sql_module)

        collector = gcp_sql_module.GCPCloudSQLCollector(project_id="test-project")

        with patch.object(collector, "_get_service", return_value=mock_gcp_sql_service_isolated):
            assets = collector.collect()

            assert len(assets) == 1
            instance = assets[0]
            assert instance.network_exposure == NETWORK_EXPOSURE_ISOLATED
            assert instance.raw_config["has_public_ip"] is False
            assert instance.raw_config["has_private_network"] is False


# Fixtures for GCP Cloud SQL tests

@pytest.fixture
def mock_gcp_sql_service():
    """Return a mocked Cloud SQL Admin API service with sample responses."""
    service = MagicMock()

    # Sample Cloud SQL instance response
    mock_request = MagicMock()
    mock_request.execute.return_value = {
        "items": [
            {
                "name": "production-db",
                "selfLink": "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances/production-db",
                "region": "us-central1",
                "databaseVersion": "POSTGRES_14",
                "instanceType": "CLOUD_SQL_INSTANCE",
                "state": "RUNNABLE",
                "createTime": "2024-01-01T00:00:00.000Z",
                "settings": {
                    "tier": "db-custom-2-8192",
                    "availabilityType": "REGIONAL",
                    "userLabels": {
                        "environment": "production",
                        "team": "platform",
                    },
                    "ipConfiguration": {
                        "requireSsl": True,
                        "sslMode": "ENCRYPTED_ONLY",
                        "ipv4Enabled": True,
                        "privateNetwork": "",
                        "authorizedNetworks": [
                            {"name": "office", "value": "10.0.0.0/8"},
                        ],
                    },
                    "backupConfiguration": {
                        "enabled": True,
                        "binaryLogEnabled": True,
                        "pointInTimeRecoveryEnabled": True,
                        "transactionLogRetentionDays": 7,
                    },
                    "databaseFlags": [
                        {"name": "log_connections", "value": "on"},
                        {"name": "log_disconnections", "value": "on"},
                    ],
                    "maintenanceWindow": {
                        "day": 7,
                        "hour": 2,
                    },
                },
                "ipAddresses": [
                    {"type": "PRIMARY", "ipAddress": "34.123.45.67"},
                ],
                "serverCaCert": {
                    "expirationTime": "2025-01-01T00:00:00.000Z",
                },
            }
        ]
    }

    service.instances.return_value.list.return_value = mock_request
    return service


@pytest.fixture
def mock_gcp_sql_service_private():
    """Return a mocked service for a private Cloud SQL instance."""
    service = MagicMock()

    mock_request = MagicMock()
    mock_request.execute.return_value = {
        "items": [
            {
                "name": "private-db",
                "selfLink": "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances/private-db",
                "region": "us-central1",
                "databaseVersion": "MYSQL_8_0",
                "instanceType": "CLOUD_SQL_INSTANCE",
                "state": "RUNNABLE",
                "settings": {
                    "tier": "db-n1-standard-2",
                    "availabilityType": "ZONAL",
                    "userLabels": {},
                    "ipConfiguration": {
                        "requireSsl": True,
                        "ipv4Enabled": False,
                        "privateNetwork": "projects/test-project/global/networks/vpc-main",
                        "authorizedNetworks": [],
                    },
                    "backupConfiguration": {
                        "enabled": True,
                    },
                    "databaseFlags": [],
                },
                "ipAddresses": [
                    {"type": "PRIVATE", "ipAddress": "10.128.0.5"},
                ],
            }
        ]
    }

    service.instances.return_value.list.return_value = mock_request
    return service


@pytest.fixture
def mock_gcp_sql_service_public():
    """Return a mocked service for a public Cloud SQL instance allowing 0.0.0.0/0."""
    service = MagicMock()

    mock_request = MagicMock()
    mock_request.execute.return_value = {
        "items": [
            {
                "name": "public-db",
                "selfLink": "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances/public-db",
                "region": "us-central1",
                "databaseVersion": "POSTGRES_14",
                "instanceType": "CLOUD_SQL_INSTANCE",
                "state": "RUNNABLE",
                "settings": {
                    "tier": "db-f1-micro",
                    "availabilityType": "ZONAL",
                    "userLabels": {},
                    "ipConfiguration": {
                        "requireSsl": False,
                        "ipv4Enabled": True,
                        "authorizedNetworks": [
                            {"name": "all", "value": "0.0.0.0/0"},
                        ],
                    },
                    "backupConfiguration": {
                        "enabled": False,
                    },
                    "databaseFlags": [],
                },
                "ipAddresses": [
                    {"type": "PRIMARY", "ipAddress": "35.200.100.50"},
                ],
            }
        ]
    }

    service.instances.return_value.list.return_value = mock_request
    return service


@pytest.fixture
def mock_gcp_sql_service_cmek():
    """Return a mocked service for a Cloud SQL instance with CMEK encryption."""
    service = MagicMock()

    mock_request = MagicMock()
    mock_request.execute.return_value = {
        "items": [
            {
                "name": "encrypted-db",
                "selfLink": "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances/encrypted-db",
                "region": "us-central1",
                "databaseVersion": "POSTGRES_14",
                "instanceType": "CLOUD_SQL_INSTANCE",
                "state": "RUNNABLE",
                "settings": {
                    "tier": "db-custom-4-16384",
                    "availabilityType": "REGIONAL",
                    "userLabels": {},
                    "ipConfiguration": {
                        "requireSsl": True,
                        "ipv4Enabled": False,
                        "privateNetwork": "projects/test-project/global/networks/vpc-main",
                        "authorizedNetworks": [],
                    },
                    "backupConfiguration": {
                        "enabled": True,
                    },
                    "databaseFlags": [],
                },
                "diskEncryptionConfiguration": {
                    "kmsKeyName": "projects/test-project/locations/us-central1/keyRings/db-keys/cryptoKeys/sql-key",
                },
                "ipAddresses": [
                    {"type": "PRIVATE", "ipAddress": "10.128.0.10"},
                ],
            }
        ]
    }

    service.instances.return_value.list.return_value = mock_request
    return service


@pytest.fixture
def mock_gcp_sql_service_empty():
    """Return a mocked service with no instances."""
    service = MagicMock()

    mock_request = MagicMock()
    mock_request.execute.return_value = {"items": []}

    service.instances.return_value.list.return_value = mock_request
    return service


@pytest.fixture
def mock_gcp_sql_service_error():
    """Return a mocked service that raises an error."""
    service = MagicMock()

    mock_request = MagicMock()
    mock_request.execute.side_effect = Exception("API Error: Access Denied")

    service.instances.return_value.list.return_value = mock_request
    return service


@pytest.fixture
def mock_gcp_sql_service_isolated():
    """Return a mocked service for an isolated Cloud SQL instance (no public or private network)."""
    service = MagicMock()

    mock_request = MagicMock()
    mock_request.execute.return_value = {
        "items": [
            {
                "name": "isolated-db",
                "selfLink": "https://sqladmin.googleapis.com/sql/v1/projects/test-project/instances/isolated-db",
                "region": "us-central1",
                "databaseVersion": "POSTGRES_14",
                "instanceType": "CLOUD_SQL_INSTANCE",
                "state": "RUNNABLE",
                "settings": {
                    "tier": "db-f1-micro",
                    "availabilityType": "ZONAL",
                    "userLabels": {},
                    "ipConfiguration": {
                        "requireSsl": True,
                        "ipv4Enabled": False,
                        "privateNetwork": "",
                        "authorizedNetworks": [],
                    },
                    "backupConfiguration": {
                        "enabled": True,
                    },
                    "databaseFlags": [],
                },
                "ipAddresses": [],
            }
        ]
    }

    service.instances.return_value.list.return_value = mock_request
    return service
