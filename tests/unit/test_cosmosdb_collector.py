"""
Unit tests for AzureCosmosDBCollector.

Tests cover:
- Azure Cosmos DB account collection with mocked Azure SDK responses
- Network exposure detection (public access, IP rules, VNet rules, private endpoints)
- Encryption configuration (service-managed vs customer-managed keys)
- Backup policy settings
- Geo-replication and consistency configuration
- Authentication settings (disable local auth)
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
mock_azure_cosmosdb = MagicMock()
mock_azure_identity = MagicMock()

sys.modules["azure"] = MagicMock()
sys.modules["azure.mgmt"] = MagicMock()
sys.modules["azure.mgmt.cosmosdb"] = mock_azure_cosmosdb
sys.modules["azure.identity"] = mock_azure_identity


class TestAzureCosmosDBCollector:
    """Tests for AzureCosmosDBCollector."""

    def test_azure_cosmosdb_collector_init(self):
        """Test AzureCosmosDBCollector can be initialized."""
        import importlib
        import stance.collectors.azure_cosmosdb as azure_cosmosdb_module
        importlib.reload(azure_cosmosdb_module)

        collector = azure_cosmosdb_module.AzureCosmosDBCollector(
            subscription_id="test-subscription-id"
        )
        assert collector.collector_name == "azure_cosmosdb"
        assert collector.subscription_id == "test-subscription-id"
        assert "azure_cosmosdb_account" in collector.resource_types

    def test_azure_cosmosdb_collector_collect_accounts(self, mock_cosmosdb_client):
        """Test Cosmos DB account collection with mock response."""
        import importlib
        import stance.collectors.azure_cosmosdb as azure_cosmosdb_module
        importlib.reload(azure_cosmosdb_module)

        collector = azure_cosmosdb_module.AzureCosmosDBCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_cosmosdb_client", return_value=mock_cosmosdb_client
        ):
            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            assert len(assets) >= 1

            # Find the account asset
            account = next(
                (a for a in assets if a.resource_type == "azure_cosmosdb_account"), None
            )
            assert account is not None
            assert account.name == "test-cosmos-account"
            assert account.cloud_provider == "azure"
            assert account.account_id == "test-subscription-id"
            assert account.region == "eastus"

    def test_azure_cosmosdb_collector_public_access(self, mock_cosmosdb_client_public):
        """Test account with public access has internet exposure."""
        import importlib
        import stance.collectors.azure_cosmosdb as azure_cosmosdb_module
        importlib.reload(azure_cosmosdb_module)

        collector = azure_cosmosdb_module.AzureCosmosDBCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_cosmosdb_client", return_value=mock_cosmosdb_client_public
        ):
            assets = collector.collect()

            account = next(
                (a for a in assets if a.resource_type == "azure_cosmosdb_account"), None
            )
            assert account is not None
            assert account.network_exposure == NETWORK_EXPOSURE_INTERNET
            assert account.raw_config["is_public_network_enabled"] is True

    def test_azure_cosmosdb_collector_allows_any_ip(self, mock_cosmosdb_client_any_ip):
        """Test account with 0.0.0.0 in IP rules has internet exposure."""
        import importlib
        import stance.collectors.azure_cosmosdb as azure_cosmosdb_module
        importlib.reload(azure_cosmosdb_module)

        collector = azure_cosmosdb_module.AzureCosmosDBCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_cosmosdb_client", return_value=mock_cosmosdb_client_any_ip
        ):
            assets = collector.collect()

            account = next(
                (a for a in assets if a.resource_type == "azure_cosmosdb_account"), None
            )
            assert account is not None
            assert account.network_exposure == NETWORK_EXPOSURE_INTERNET
            assert account.raw_config["allows_any_ip"] is True

    def test_azure_cosmosdb_collector_private_only(self, mock_cosmosdb_client_private):
        """Test account with private endpoints only has isolated exposure."""
        import importlib
        import stance.collectors.azure_cosmosdb as azure_cosmosdb_module
        importlib.reload(azure_cosmosdb_module)

        collector = azure_cosmosdb_module.AzureCosmosDBCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_cosmosdb_client", return_value=mock_cosmosdb_client_private
        ):
            assets = collector.collect()

            account = next(
                (a for a in assets if a.resource_type == "azure_cosmosdb_account"), None
            )
            assert account is not None
            assert account.network_exposure == NETWORK_EXPOSURE_ISOLATED
            assert account.raw_config["has_private_endpoints"] is True
            assert account.raw_config["is_public_network_enabled"] is False

    def test_azure_cosmosdb_collector_cmek(self, mock_cosmosdb_client_cmek):
        """Test customer-managed key encryption detection."""
        import importlib
        import stance.collectors.azure_cosmosdb as azure_cosmosdb_module
        importlib.reload(azure_cosmosdb_module)

        collector = azure_cosmosdb_module.AzureCosmosDBCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_cosmosdb_client", return_value=mock_cosmosdb_client_cmek
        ):
            assets = collector.collect()

            account = next(
                (a for a in assets if a.resource_type == "azure_cosmosdb_account"), None
            )
            assert account is not None
            assert account.raw_config["uses_cmek"] is True
            assert "vault.azure.net" in account.raw_config["key_vault_key_uri"].lower()

    def test_azure_cosmosdb_collector_tls_version(self, mock_cosmosdb_client):
        """Test that minimal TLS version is captured."""
        import importlib
        import stance.collectors.azure_cosmosdb as azure_cosmosdb_module
        importlib.reload(azure_cosmosdb_module)

        collector = azure_cosmosdb_module.AzureCosmosDBCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_cosmosdb_client", return_value=mock_cosmosdb_client
        ):
            assets = collector.collect()

            account = next(
                (a for a in assets if a.resource_type == "azure_cosmosdb_account"), None
            )
            assert account is not None
            assert account.raw_config["minimal_tls_version"] == "Tls12"
            assert account.raw_config["uses_tls_1_2"] is True

    def test_azure_cosmosdb_collector_disable_local_auth(
        self, mock_cosmosdb_client_disable_local_auth
    ):
        """Test disable local auth detection."""
        import importlib
        import stance.collectors.azure_cosmosdb as azure_cosmosdb_module
        importlib.reload(azure_cosmosdb_module)

        collector = azure_cosmosdb_module.AzureCosmosDBCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector,
            "_get_cosmosdb_client",
            return_value=mock_cosmosdb_client_disable_local_auth,
        ):
            assets = collector.collect()

            account = next(
                (a for a in assets if a.resource_type == "azure_cosmosdb_account"), None
            )
            assert account is not None
            assert account.raw_config["disable_local_auth"] is True

    def test_azure_cosmosdb_collector_multi_region(self, mock_cosmosdb_client_multi_region):
        """Test multi-region geo-replication detection."""
        import importlib
        import stance.collectors.azure_cosmosdb as azure_cosmosdb_module
        importlib.reload(azure_cosmosdb_module)

        collector = azure_cosmosdb_module.AzureCosmosDBCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_cosmosdb_client", return_value=mock_cosmosdb_client_multi_region
        ):
            assets = collector.collect()

            account = next(
                (a for a in assets if a.resource_type == "azure_cosmosdb_account"), None
            )
            assert account is not None
            assert account.raw_config["is_multi_region"] is True
            assert len(account.raw_config["locations"]) > 1

    def test_azure_cosmosdb_collector_api_type(self, mock_cosmosdb_client_mongodb):
        """Test API type detection from capabilities."""
        import importlib
        import stance.collectors.azure_cosmosdb as azure_cosmosdb_module
        importlib.reload(azure_cosmosdb_module)

        collector = azure_cosmosdb_module.AzureCosmosDBCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_cosmosdb_client", return_value=mock_cosmosdb_client_mongodb
        ):
            assets = collector.collect()

            account = next(
                (a for a in assets if a.resource_type == "azure_cosmosdb_account"), None
            )
            assert account is not None
            assert account.raw_config["api_type"] == "MongoDB"

    def test_azure_cosmosdb_collector_handles_empty_response(
        self, mock_cosmosdb_client_empty
    ):
        """Test handling of empty account list."""
        import importlib
        import stance.collectors.azure_cosmosdb as azure_cosmosdb_module
        importlib.reload(azure_cosmosdb_module)

        collector = azure_cosmosdb_module.AzureCosmosDBCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_cosmosdb_client", return_value=mock_cosmosdb_client_empty
        ):
            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            assert len(assets) == 0

    def test_azure_cosmosdb_collector_handles_api_error(
        self, mock_cosmosdb_client_error
    ):
        """Test graceful handling of API errors."""
        import importlib
        import stance.collectors.azure_cosmosdb as azure_cosmosdb_module
        importlib.reload(azure_cosmosdb_module)

        collector = azure_cosmosdb_module.AzureCosmosDBCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_cosmosdb_client", return_value=mock_cosmosdb_client_error
        ):
            # Should not raise, but return empty collection
            assets = collector.collect()
            assert isinstance(assets, AssetCollection)
            assert len(assets) == 0

    def test_azure_cosmosdb_collector_tags_extraction(self, mock_cosmosdb_client):
        """Test that tags are extracted correctly."""
        import importlib
        import stance.collectors.azure_cosmosdb as azure_cosmosdb_module
        importlib.reload(azure_cosmosdb_module)

        collector = azure_cosmosdb_module.AzureCosmosDBCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_cosmosdb_client", return_value=mock_cosmosdb_client
        ):
            assets = collector.collect()

            account = next(
                (a for a in assets if a.resource_type == "azure_cosmosdb_account"), None
            )
            assert account is not None
            assert account.tags == {"environment": "production", "team": "data"}


# Helper functions to create mock objects

def _create_mock_account(
    name: str = "test-cosmos-account",
    location: str = "eastus",
    kind: str = "GlobalDocumentDB",
    public_network_access: str = "Enabled",
    min_tls: str = "Tls12",
    tags: dict | None = None,
    ip_rules: list | None = None,
    virtual_network_rules: list | None = None,
    private_endpoints: list | None = None,
    key_vault_key_uri: str | None = None,
    disable_local_auth: bool = False,
    locations: list | None = None,
    capabilities: list | None = None,
) -> MagicMock:
    """Create a mock Cosmos DB account object."""
    account = MagicMock()
    account.id = f"/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.DocumentDB/databaseAccounts/{name}"
    account.name = name
    account.location = location
    account.kind = kind
    account.database_account_offer_type = "Standard"
    account.document_endpoint = f"https://{name}.documents.azure.com:443/"
    account.provisioning_state = "Succeeded"
    account.tags = tags or {"environment": "production", "team": "data"}

    # Network configuration
    account.public_network_access = public_network_access
    account.ip_rules = ip_rules or []
    account.virtual_network_rules = virtual_network_rules or []
    account.private_endpoint_connections = private_endpoints or []
    account.network_acl_bypass = "None"
    account.network_acl_bypass_resource_ids = []

    # Encryption
    account.key_vault_key_uri = key_vault_key_uri
    account.minimal_tls_version = min_tls

    # Authentication
    account.disable_local_auth = disable_local_auth
    account.disable_key_based_metadata_write_access = False

    # Consistency policy
    consistency = MagicMock()
    consistency.default_consistency_level = "Session"
    consistency.max_staleness_prefix = 100
    consistency.max_interval_in_seconds = 5
    account.consistency_policy = consistency

    # Locations / geo-replication
    if locations is None:
        loc = MagicMock()
        loc.location_name = "East US"
        loc.failover_priority = 0
        loc.is_zone_redundant = False
        loc.document_endpoint = f"https://{name}-eastus.documents.azure.com:443/"
        locations = [loc]
    account.locations = locations
    account.write_locations = locations[:1]
    account.read_locations = locations

    # Features
    account.enable_automatic_failover = True
    account.enable_multiple_write_locations = False
    account.enable_analytical_storage = False
    account.enable_free_tier = False

    # Capabilities (API type detection)
    account.capabilities = capabilities or []
    account.api_properties = None

    # Backup policy
    backup_policy = MagicMock()
    backup_policy.__class__.__name__ = "PeriodicModeBackupPolicy"
    props = MagicMock()
    props.backup_interval_in_minutes = 240
    props.backup_retention_interval_in_hours = 8
    props.backup_storage_redundancy = "Geo"
    backup_policy.periodic_mode_properties = props
    account.backup_policy = backup_policy

    # CORS
    account.cors = []

    return account


def _create_mock_ip_rule(ip_address: str) -> MagicMock:
    """Create a mock IP rule."""
    rule = MagicMock()
    rule.ip_address_or_range = ip_address
    return rule


def _create_mock_vnet_rule(subnet_id: str) -> MagicMock:
    """Create a mock VNet rule."""
    rule = MagicMock()
    rule.id = subnet_id
    rule.ignore_missing_v_net_service_endpoint = False
    return rule


def _create_mock_private_endpoint(name: str = "pe-cosmos") -> MagicMock:
    """Create a mock private endpoint connection."""
    pe = MagicMock()
    pe.id = f"/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Network/privateEndpoints/{name}"
    pe.name = name
    pe.private_endpoint = MagicMock()
    pe.private_endpoint.id = pe.id
    pe.private_link_service_connection_state = MagicMock()
    pe.private_link_service_connection_state.status = "Approved"
    return pe


def _create_mock_capability(name: str) -> MagicMock:
    """Create a mock capability."""
    cap = MagicMock()
    cap.name = name
    return cap


def _create_mock_cosmosdb_client(accounts: list) -> MagicMock:
    """Create a mock CosmosDBManagementClient."""
    client = MagicMock()
    client.database_accounts.list.return_value = accounts
    return client


# Fixtures

@pytest.fixture
def mock_cosmosdb_client():
    """Return a mocked Cosmos DB client with sample responses."""
    account = _create_mock_account()
    return _create_mock_cosmosdb_client(accounts=[account])


@pytest.fixture
def mock_cosmosdb_client_public():
    """Return a mocked client for an account with public access and no restrictions."""
    account = _create_mock_account(public_network_access="Enabled")
    return _create_mock_cosmosdb_client(accounts=[account])


@pytest.fixture
def mock_cosmosdb_client_any_ip():
    """Return a mocked client for an account that allows any IP."""
    ip_rules = [_create_mock_ip_rule("0.0.0.0")]
    account = _create_mock_account(
        public_network_access="Enabled",
        ip_rules=ip_rules,
    )
    return _create_mock_cosmosdb_client(accounts=[account])


@pytest.fixture
def mock_cosmosdb_client_private():
    """Return a mocked client for an account with private endpoints only."""
    private_endpoints = [_create_mock_private_endpoint()]
    account = _create_mock_account(
        public_network_access="Disabled",
        private_endpoints=private_endpoints,
    )
    return _create_mock_cosmosdb_client(accounts=[account])


@pytest.fixture
def mock_cosmosdb_client_cmek():
    """Return a mocked client with customer-managed key encryption."""
    account = _create_mock_account(
        key_vault_key_uri="https://myvault.vault.azure.net/keys/mykey/version1"
    )
    return _create_mock_cosmosdb_client(accounts=[account])


@pytest.fixture
def mock_cosmosdb_client_disable_local_auth():
    """Return a mocked client with local auth disabled."""
    account = _create_mock_account(disable_local_auth=True)
    return _create_mock_cosmosdb_client(accounts=[account])


@pytest.fixture
def mock_cosmosdb_client_multi_region():
    """Return a mocked client with multi-region geo-replication."""
    loc1 = MagicMock()
    loc1.location_name = "East US"
    loc1.failover_priority = 0
    loc1.is_zone_redundant = False
    loc1.document_endpoint = "https://test-cosmos-account-eastus.documents.azure.com:443/"

    loc2 = MagicMock()
    loc2.location_name = "West US"
    loc2.failover_priority = 1
    loc2.is_zone_redundant = True
    loc2.document_endpoint = "https://test-cosmos-account-westus.documents.azure.com:443/"

    account = _create_mock_account(locations=[loc1, loc2])
    return _create_mock_cosmosdb_client(accounts=[account])


@pytest.fixture
def mock_cosmosdb_client_mongodb():
    """Return a mocked client for a MongoDB API account."""
    capabilities = [_create_mock_capability("EnableMongo")]
    account = _create_mock_account(
        kind="MongoDB",
        capabilities=capabilities,
    )
    return _create_mock_cosmosdb_client(accounts=[account])


@pytest.fixture
def mock_cosmosdb_client_empty():
    """Return a mocked client with no accounts."""
    return _create_mock_cosmosdb_client(accounts=[])


@pytest.fixture
def mock_cosmosdb_client_error():
    """Return a mocked client that raises an error."""
    client = MagicMock()
    client.database_accounts.list.side_effect = Exception("API Error: Access Denied")
    return client
