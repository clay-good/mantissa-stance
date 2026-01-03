"""
Unit tests for AzureSQLCollector.

Tests cover:
- Azure SQL server collection with mocked Azure SDK responses
- Azure SQL database collection
- Firewall rules and network exposure detection
- Encryption and TDE configuration
- Auditing and threat detection settings
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


# Mock the Azure dependencies at module level before importing the collector
mock_azure_sql = MagicMock()
mock_azure_identity = MagicMock()

sys.modules["azure"] = MagicMock()
sys.modules["azure.mgmt"] = MagicMock()
sys.modules["azure.mgmt.sql"] = mock_azure_sql
sys.modules["azure.identity"] = mock_azure_identity


class TestAzureSQLCollector:
    """Tests for AzureSQLCollector."""

    def test_azure_sql_collector_init(self):
        """Test AzureSQLCollector can be initialized."""
        import importlib
        import stance.collectors.azure_sql as azure_sql_module
        importlib.reload(azure_sql_module)

        collector = azure_sql_module.AzureSQLCollector(
            subscription_id="test-subscription-id"
        )
        assert collector.collector_name == "azure_sql"
        assert collector.subscription_id == "test-subscription-id"
        assert "azure_sql_server" in collector.resource_types
        assert "azure_sql_database" in collector.resource_types

    def test_azure_sql_collector_collect_servers(self, mock_azure_sql_client):
        """Test SQL server collection with mock response."""
        import importlib
        import stance.collectors.azure_sql as azure_sql_module
        importlib.reload(azure_sql_module)

        collector = azure_sql_module.AzureSQLCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_sql_client", return_value=mock_azure_sql_client
        ):
            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            assert len(assets) >= 1

            # Find the server asset
            server = next(
                (a for a in assets if a.resource_type == "azure_sql_server"), None
            )
            assert server is not None
            assert server.name == "test-sql-server"
            assert server.cloud_provider == "azure"
            assert server.account_id == "test-subscription-id"
            assert server.region == "eastus"

    def test_azure_sql_collector_collects_databases(self, mock_azure_sql_client):
        """Test that databases are collected for each server."""
        import importlib
        import stance.collectors.azure_sql as azure_sql_module
        importlib.reload(azure_sql_module)

        collector = azure_sql_module.AzureSQLCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_sql_client", return_value=mock_azure_sql_client
        ):
            assets = collector.collect()

            # Should have both server and database
            db_assets = [a for a in assets if a.resource_type == "azure_sql_database"]
            assert len(db_assets) >= 1

            db = db_assets[0]
            assert db.name == "test-database"
            assert db.raw_config["server_name"] == "test-sql-server"

    def test_azure_sql_collector_public_access(self, mock_azure_sql_client_public):
        """Test server with public access has internet exposure."""
        import importlib
        import stance.collectors.azure_sql as azure_sql_module
        importlib.reload(azure_sql_module)

        collector = azure_sql_module.AzureSQLCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_sql_client", return_value=mock_azure_sql_client_public
        ):
            assets = collector.collect()

            server = next(
                (a for a in assets if a.resource_type == "azure_sql_server"), None
            )
            assert server is not None
            assert server.network_exposure == NETWORK_EXPOSURE_INTERNET
            assert server.raw_config["allows_any_ip"] is True

    def test_azure_sql_collector_private_only(self, mock_azure_sql_client_private):
        """Test server with private endpoints only has internal exposure."""
        import importlib
        import stance.collectors.azure_sql as azure_sql_module
        importlib.reload(azure_sql_module)

        collector = azure_sql_module.AzureSQLCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_sql_client", return_value=mock_azure_sql_client_private
        ):
            assets = collector.collect()

            server = next(
                (a for a in assets if a.resource_type == "azure_sql_server"), None
            )
            assert server is not None
            assert server.network_exposure == NETWORK_EXPOSURE_INTERNAL
            assert server.raw_config["has_private_endpoints"] is True

    def test_azure_sql_collector_tls_version(self, mock_azure_sql_client):
        """Test that minimal TLS version is captured."""
        import importlib
        import stance.collectors.azure_sql as azure_sql_module
        importlib.reload(azure_sql_module)

        collector = azure_sql_module.AzureSQLCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_sql_client", return_value=mock_azure_sql_client
        ):
            assets = collector.collect()

            server = next(
                (a for a in assets if a.resource_type == "azure_sql_server"), None
            )
            assert server is not None
            assert server.raw_config["minimal_tls_version"] == "1.2"
            assert server.raw_config["uses_tls_1_2"] is True

    def test_azure_sql_collector_azure_ad_auth(self, mock_azure_sql_client_aad):
        """Test Azure AD only authentication detection."""
        import importlib
        import stance.collectors.azure_sql as azure_sql_module
        importlib.reload(azure_sql_module)

        collector = azure_sql_module.AzureSQLCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_sql_client", return_value=mock_azure_sql_client_aad
        ):
            assets = collector.collect()

            server = next(
                (a for a in assets if a.resource_type == "azure_sql_server"), None
            )
            assert server is not None
            assert server.raw_config["azure_ad_only_authentication"] is True

    def test_azure_sql_collector_encryption(self, mock_azure_sql_client_cmk):
        """Test customer-managed key encryption detection."""
        import importlib
        import stance.collectors.azure_sql as azure_sql_module
        importlib.reload(azure_sql_module)

        collector = azure_sql_module.AzureSQLCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_sql_client", return_value=mock_azure_sql_client_cmk
        ):
            assets = collector.collect()

            server = next(
                (a for a in assets if a.resource_type == "azure_sql_server"), None
            )
            assert server is not None
            assert server.raw_config["uses_customer_managed_key"] is True

    def test_azure_sql_collector_auditing(self, mock_azure_sql_client_audit):
        """Test auditing configuration detection."""
        import importlib
        import stance.collectors.azure_sql as azure_sql_module
        importlib.reload(azure_sql_module)

        collector = azure_sql_module.AzureSQLCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_sql_client", return_value=mock_azure_sql_client_audit
        ):
            assets = collector.collect()

            server = next(
                (a for a in assets if a.resource_type == "azure_sql_server"), None
            )
            assert server is not None
            assert server.raw_config["auditing_enabled"] is True

    def test_azure_sql_collector_threat_detection(self, mock_azure_sql_client_threat):
        """Test threat detection configuration."""
        import importlib
        import stance.collectors.azure_sql as azure_sql_module
        importlib.reload(azure_sql_module)

        collector = azure_sql_module.AzureSQLCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_sql_client", return_value=mock_azure_sql_client_threat
        ):
            assets = collector.collect()

            server = next(
                (a for a in assets if a.resource_type == "azure_sql_server"), None
            )
            assert server is not None
            assert server.raw_config["threat_detection_enabled"] is True

    def test_azure_sql_collector_handles_empty_response(
        self, mock_azure_sql_client_empty
    ):
        """Test handling of empty server list."""
        import importlib
        import stance.collectors.azure_sql as azure_sql_module
        importlib.reload(azure_sql_module)

        collector = azure_sql_module.AzureSQLCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_sql_client", return_value=mock_azure_sql_client_empty
        ):
            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            assert len(assets) == 0

    def test_azure_sql_collector_handles_api_error(self, mock_azure_sql_client_error):
        """Test graceful handling of API errors."""
        import importlib
        import stance.collectors.azure_sql as azure_sql_module
        importlib.reload(azure_sql_module)

        collector = azure_sql_module.AzureSQLCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_sql_client", return_value=mock_azure_sql_client_error
        ):
            # Should not raise, but return empty collection
            assets = collector.collect()
            assert isinstance(assets, AssetCollection)
            assert len(assets) == 0

    def test_azure_sql_collector_tags_extraction(self, mock_azure_sql_client):
        """Test that tags are extracted correctly."""
        import importlib
        import stance.collectors.azure_sql as azure_sql_module
        importlib.reload(azure_sql_module)

        collector = azure_sql_module.AzureSQLCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_sql_client", return_value=mock_azure_sql_client
        ):
            assets = collector.collect()

            server = next(
                (a for a in assets if a.resource_type == "azure_sql_server"), None
            )
            assert server is not None
            assert server.tags == {"environment": "production", "team": "data"}


# Helper function to create mock server
def _create_mock_server(
    name: str = "test-sql-server",
    location: str = "eastus",
    public_network_access: str = "Enabled",
    min_tls: str = "1.2",
    tags: dict | None = None,
    administrators: MagicMock | None = None,
    private_endpoints: list | None = None,
) -> MagicMock:
    """Create a mock SQL server object."""
    server = MagicMock()
    server.id = f"/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Sql/servers/{name}"
    server.name = name
    server.location = location
    server.kind = "v12.0"
    server.version = "12.0"
    server.state = "Ready"
    server.fully_qualified_domain_name = f"{name}.database.windows.net"
    server.administrator_login = "sqladmin"
    server.workspace_feature = None
    server.public_network_access = public_network_access
    server.minimal_tls_version = min_tls
    server.administrators = administrators
    server.private_endpoint_connections = private_endpoints or []
    server.tags = tags or {"environment": "production", "team": "data"}
    return server


def _create_mock_database(
    name: str = "test-database",
    location: str = "eastus",
) -> MagicMock:
    """Create a mock SQL database object."""
    db = MagicMock()
    db.id = f"/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-sql-server/databases/{name}"
    db.name = name
    db.location = location
    db.kind = "v12.0,user"
    db.sku = MagicMock()
    db.sku.name = "S0"
    db.sku.tier = "Standard"
    db.sku.capacity = 10
    db.status = "Online"
    db.creation_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
    db.max_size_bytes = 268435456000
    db.current_service_objective_name = "S0"
    db.collation = "SQL_Latin1_General_CP1_CI_AS"
    db.catalog_collation = "SQL_Latin1_General_CP1_CI_AS"
    db.zone_redundant = False
    db.read_scale = "Disabled"
    db.high_availability_replica_count = 0
    db.secondary_type = None
    db.failover_group_id = None
    db.earliest_restore_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
    db.requested_backup_storage_redundancy = "Geo"
    db.current_backup_storage_redundancy = "Geo"
    db.license_type = "LicenseIncluded"
    db.is_ledger_on = False
    db.maintenance_configuration_id = None
    db.tags = {}
    return db


def _create_mock_firewall_rule(
    name: str, start_ip: str, end_ip: str
) -> MagicMock:
    """Create a mock firewall rule."""
    rule = MagicMock()
    rule.id = f"/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-sql-server/firewallRules/{name}"
    rule.name = name
    rule.start_ip_address = start_ip
    rule.end_ip_address = end_ip
    return rule


def _create_mock_sql_client(
    servers: list,
    firewall_rules: list | None = None,
    vnet_rules: list | None = None,
    auditing_state: str = "Disabled",
    threat_state: str = "Disabled",
    encryption_key_type: str = "ServiceManaged",
    databases: list | None = None,
) -> MagicMock:
    """Create a mock SqlManagementClient."""
    client = MagicMock()

    # Mock servers.list()
    client.servers.list.return_value = servers

    # Mock firewall_rules.list_by_server()
    client.firewall_rules.list_by_server.return_value = firewall_rules or []

    # Mock virtual_network_rules.list_by_server()
    client.virtual_network_rules.list_by_server.return_value = vnet_rules or []

    # Mock server_blob_auditing_policies.get()
    auditing = MagicMock()
    auditing.state = auditing_state
    auditing.storage_endpoint = "https://storage.blob.core.windows.net"
    auditing.storage_account_subscription_id = "test-sub"
    auditing.retention_days = 90
    auditing.audit_actions_and_groups = []
    auditing.is_storage_secondary_key_in_use = False
    auditing.is_azure_monitor_target_enabled = True
    auditing.queue_delay_ms = 1000
    auditing.is_devops_audit_enabled = False
    client.server_blob_auditing_policies.get.return_value = auditing

    # Mock server_advanced_threat_protection_settings.get()
    threat = MagicMock()
    threat.state = threat_state
    threat.creation_time = datetime(2024, 1, 1, tzinfo=timezone.utc)
    client.server_advanced_threat_protection_settings.get.return_value = threat

    # Mock encryption_protectors.get()
    encryption = MagicMock()
    encryption.kind = encryption_key_type
    encryption.server_key_name = "ServiceManaged"
    encryption.server_key_type = encryption_key_type
    encryption.uri = None
    encryption.thumbprint = None
    encryption.auto_rotation_enabled = False
    client.encryption_protectors.get.return_value = encryption

    # Mock server_vulnerability_assessments.get()
    vuln = MagicMock()
    vuln.storage_container_path = None
    vuln.storage_container_sas_key = None
    vuln.storage_account_access_key = None
    vuln.recurring_scans = None
    client.server_vulnerability_assessments.get.return_value = vuln

    # Mock databases.list_by_server()
    if databases is None:
        databases = [_create_mock_database()]
    client.databases.list_by_server.return_value = databases

    # Mock transparent_data_encryptions.get()
    tde = MagicMock()
    tde.state = "Enabled"
    client.transparent_data_encryptions.get.return_value = tde

    return client


# Fixtures

@pytest.fixture
def mock_azure_sql_client():
    """Return a mocked Azure SQL client with sample responses."""
    server = _create_mock_server()
    return _create_mock_sql_client(servers=[server])


@pytest.fixture
def mock_azure_sql_client_public():
    """Return a mocked client for a server with public access."""
    server = _create_mock_server(public_network_access="Enabled")
    firewall_rules = [
        _create_mock_firewall_rule("AllowAll", "0.0.0.0", "255.255.255.255")
    ]
    return _create_mock_sql_client(servers=[server], firewall_rules=firewall_rules)


@pytest.fixture
def mock_azure_sql_client_private():
    """Return a mocked client for a server with private endpoints only."""
    private_endpoint = MagicMock()
    private_endpoint.id = "/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Network/privateEndpoints/pe-sql"
    private_endpoint.name = "pe-sql"
    private_endpoint.private_endpoint = MagicMock()
    private_endpoint.private_endpoint.id = "/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Network/privateEndpoints/pe-sql"
    private_endpoint.private_link_service_connection_state = MagicMock()
    private_endpoint.private_link_service_connection_state.status = "Approved"

    server = _create_mock_server(
        public_network_access="Disabled",
        private_endpoints=[private_endpoint],
    )
    return _create_mock_sql_client(servers=[server])


@pytest.fixture
def mock_azure_sql_client_aad():
    """Return a mocked client with Azure AD only auth enabled."""
    admin = MagicMock()
    admin.administrator_type = "ActiveDirectory"
    admin.principal_type = "Group"
    admin.login = "sql-admins"
    admin.sid = "00000000-0000-0000-0000-000000000001"
    admin.tenant_id = "00000000-0000-0000-0000-000000000002"
    admin.azure_ad_only_authentication = True

    server = _create_mock_server(administrators=admin)
    return _create_mock_sql_client(servers=[server])


@pytest.fixture
def mock_azure_sql_client_cmk():
    """Return a mocked client with customer-managed key encryption."""
    server = _create_mock_server()
    return _create_mock_sql_client(
        servers=[server],
        encryption_key_type="AzureKeyVault",
    )


@pytest.fixture
def mock_azure_sql_client_audit():
    """Return a mocked client with auditing enabled."""
    server = _create_mock_server()
    return _create_mock_sql_client(servers=[server], auditing_state="Enabled")


@pytest.fixture
def mock_azure_sql_client_threat():
    """Return a mocked client with threat detection enabled."""
    server = _create_mock_server()
    return _create_mock_sql_client(servers=[server], threat_state="Enabled")


@pytest.fixture
def mock_azure_sql_client_empty():
    """Return a mocked client with no servers."""
    return _create_mock_sql_client(servers=[])


@pytest.fixture
def mock_azure_sql_client_error():
    """Return a mocked client that raises an error."""
    client = MagicMock()
    client.servers.list.side_effect = Exception("API Error: Access Denied")
    return client
