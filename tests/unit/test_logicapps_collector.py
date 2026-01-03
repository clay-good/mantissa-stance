"""
Unit tests for AzureLogicAppsCollector.

Tests cover:
- Azure Logic Apps collection with mocked Azure SDK responses
- Workflow state detection (enabled/disabled)
- Access control configuration (IP restrictions)
- Trigger detection (HTTP, recurrence, event-based)
- Managed identity configuration
- Integration Service Environment (ISE)
- Network exposure detection
- Definition analysis (connections, triggers, actions)
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
mock_azure_logic = MagicMock()
mock_azure_identity = MagicMock()

sys.modules["azure"] = MagicMock()
sys.modules["azure.mgmt"] = MagicMock()
sys.modules["azure.mgmt.logic"] = mock_azure_logic
sys.modules["azure.identity"] = mock_azure_identity


class TestAzureLogicAppsCollector:
    """Tests for AzureLogicAppsCollector."""

    def test_logicapps_collector_init(self):
        """Test AzureLogicAppsCollector can be initialized."""
        import importlib
        import stance.collectors.azure_logicapps as azure_logicapps_module
        importlib.reload(azure_logicapps_module)

        collector = azure_logicapps_module.AzureLogicAppsCollector(
            subscription_id="test-subscription-id"
        )
        assert collector.collector_name == "azure_logicapps"
        assert collector.subscription_id == "test-subscription-id"
        assert "azure_logic_app" in collector.resource_types

    def test_logicapps_collector_collect_workflows(
        self, mock_azure_logic_client
    ):
        """Test Logic Apps collection with mock response."""
        import importlib
        import stance.collectors.azure_logicapps as azure_logicapps_module
        importlib.reload(azure_logicapps_module)

        collector = azure_logicapps_module.AzureLogicAppsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_logic_client", return_value=mock_azure_logic_client
        ):
            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            assert len(assets) == 1

            logic_app = assets[0]
            assert logic_app.name == "test-logic-app"
            assert logic_app.resource_type == "azure_logic_app"
            assert logic_app.cloud_provider == "azure"
            assert logic_app.account_id == "test-subscription-id"
            assert logic_app.region == "eastus"

    def test_logicapps_collector_enabled_state(
        self, mock_azure_logic_client
    ):
        """Test Logic App enabled state detection."""
        import importlib
        import stance.collectors.azure_logicapps as azure_logicapps_module
        importlib.reload(azure_logicapps_module)

        collector = azure_logicapps_module.AzureLogicAppsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_logic_client", return_value=mock_azure_logic_client
        ):
            assets = collector.collect()

            assert len(assets) == 1
            logic_app = assets[0]
            assert logic_app.raw_config["is_enabled"] is True
            assert logic_app.raw_config["state"] == "Enabled"

    def test_logicapps_collector_http_trigger_internet_facing(
        self, mock_azure_logic_client_http_trigger
    ):
        """Test Logic App with HTTP trigger is internet-facing."""
        import importlib
        import stance.collectors.azure_logicapps as azure_logicapps_module
        importlib.reload(azure_logicapps_module)

        collector = azure_logicapps_module.AzureLogicAppsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_logic_client", return_value=mock_azure_logic_client_http_trigger
        ):
            assets = collector.collect()

            assert len(assets) == 1
            logic_app = assets[0]
            assert logic_app.raw_config["has_http_trigger"] is True
            assert logic_app.network_exposure == NETWORK_EXPOSURE_INTERNET

    def test_logicapps_collector_recurrence_trigger_isolated(
        self, mock_azure_logic_client_recurrence
    ):
        """Test Logic App with recurrence trigger is isolated."""
        import importlib
        import stance.collectors.azure_logicapps as azure_logicapps_module
        importlib.reload(azure_logicapps_module)

        collector = azure_logicapps_module.AzureLogicAppsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_logic_client", return_value=mock_azure_logic_client_recurrence
        ):
            assets = collector.collect()

            assert len(assets) == 1
            logic_app = assets[0]
            assert logic_app.raw_config["has_recurrence_trigger"] is True
            assert logic_app.raw_config["has_http_trigger"] is False
            assert logic_app.network_exposure == NETWORK_EXPOSURE_ISOLATED

    def test_logicapps_collector_managed_identity(
        self, mock_azure_logic_client_identity
    ):
        """Test Logic App with managed identity."""
        import importlib
        import stance.collectors.azure_logicapps as azure_logicapps_module
        importlib.reload(azure_logicapps_module)

        collector = azure_logicapps_module.AzureLogicAppsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_logic_client", return_value=mock_azure_logic_client_identity
        ):
            assets = collector.collect()

            assert len(assets) == 1
            logic_app = assets[0]
            assert logic_app.raw_config["has_managed_identity"] is True
            assert logic_app.raw_config["uses_system_assigned_identity"] is True

    def test_logicapps_collector_ise_integration(
        self, mock_azure_logic_client_ise
    ):
        """Test Logic App with Integration Service Environment."""
        import importlib
        import stance.collectors.azure_logicapps as azure_logicapps_module
        importlib.reload(azure_logicapps_module)

        collector = azure_logicapps_module.AzureLogicAppsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_logic_client", return_value=mock_azure_logic_client_ise
        ):
            assets = collector.collect()

            assert len(assets) == 1
            logic_app = assets[0]
            assert logic_app.raw_config["has_ise"] is True
            assert logic_app.raw_config["uses_ise_isolation"] is True
            assert logic_app.network_exposure == NETWORK_EXPOSURE_INTERNAL

    def test_logicapps_collector_access_control(
        self, mock_azure_logic_client_access_control
    ):
        """Test Logic App with access control restrictions."""
        import importlib
        import stance.collectors.azure_logicapps as azure_logicapps_module
        importlib.reload(azure_logicapps_module)

        collector = azure_logicapps_module.AzureLogicAppsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_logic_client", return_value=mock_azure_logic_client_access_control
        ):
            assets = collector.collect()

            assert len(assets) == 1
            logic_app = assets[0]
            assert logic_app.raw_config["has_access_control"] is True
            assert logic_app.network_exposure == NETWORK_EXPOSURE_INTERNAL

    def test_logicapps_collector_connections_detection(
        self, mock_azure_logic_client_connections
    ):
        """Test detection of API connections used in workflow."""
        import importlib
        import stance.collectors.azure_logicapps as azure_logicapps_module
        importlib.reload(azure_logicapps_module)

        collector = azure_logicapps_module.AzureLogicAppsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_logic_client", return_value=mock_azure_logic_client_connections
        ):
            assets = collector.collect()

            assert len(assets) == 1
            logic_app = assets[0]
            assert logic_app.raw_config["connection_count"] >= 1

    def test_logicapps_collector_handles_empty_response(
        self, mock_azure_logic_client_empty
    ):
        """Test handling of empty Logic App list."""
        import importlib
        import stance.collectors.azure_logicapps as azure_logicapps_module
        importlib.reload(azure_logicapps_module)

        collector = azure_logicapps_module.AzureLogicAppsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_logic_client", return_value=mock_azure_logic_client_empty
        ):
            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            assert len(assets) == 0

    def test_logicapps_collector_handles_api_error(
        self, mock_azure_logic_client_error
    ):
        """Test graceful handling of API errors."""
        import importlib
        import stance.collectors.azure_logicapps as azure_logicapps_module
        importlib.reload(azure_logicapps_module)

        collector = azure_logicapps_module.AzureLogicAppsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_logic_client", return_value=mock_azure_logic_client_error
        ):
            # Should not raise, but return empty collection
            assets = collector.collect()
            assert isinstance(assets, AssetCollection)
            assert len(assets) == 0

    def test_logicapps_collector_tags_extraction(
        self, mock_azure_logic_client
    ):
        """Test that tags are extracted correctly."""
        import importlib
        import stance.collectors.azure_logicapps as azure_logicapps_module
        importlib.reload(azure_logicapps_module)

        collector = azure_logicapps_module.AzureLogicAppsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_logic_client", return_value=mock_azure_logic_client
        ):
            assets = collector.collect()

            assert len(assets) == 1
            logic_app = assets[0]
            assert logic_app.tags == {"environment": "production", "team": "platform"}

    def test_logicapps_collector_integration_account(
        self, mock_azure_logic_client_integration_account
    ):
        """Test Logic App with integration account."""
        import importlib
        import stance.collectors.azure_logicapps as azure_logicapps_module
        importlib.reload(azure_logicapps_module)

        collector = azure_logicapps_module.AzureLogicAppsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_logic_client", return_value=mock_azure_logic_client_integration_account
        ):
            assets = collector.collect()

            assert len(assets) == 1
            logic_app = assets[0]
            assert logic_app.raw_config["has_integration_account"] is True


# Helper functions to create mock objects

def _create_mock_workflow(
    name: str = "test-logic-app",
    location: str = "eastus",
    state: str = "Enabled",
    identity: MagicMock | None = None,
    ise: MagicMock | None = None,
    integration_account: MagicMock | None = None,
    access_control: MagicMock | None = None,
    definition: dict | None = None,
    tags: dict | None = None,
) -> MagicMock:
    """Create a mock Logic App workflow object."""
    workflow = MagicMock()
    workflow.id = f"/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Logic/workflows/{name}"
    workflow.name = name
    workflow.location = location
    workflow.state = state
    workflow.provisioning_state = "Succeeded"
    workflow.sku = MagicMock()
    workflow.sku.name = "Standard"
    workflow.version = "08585884716195265331"
    workflow.access_endpoint = f"https://prod-00.{location}.logic.azure.com:443/workflows/{name}"
    workflow.identity = identity
    workflow.integration_service_environment = ise
    workflow.integration_account = integration_account
    workflow.access_control = access_control
    workflow.endpoints_configuration = None
    workflow.parameters = {}
    workflow.created_time = datetime(2024, 1, 1, tzinfo=timezone.utc)
    workflow.changed_time = datetime(2024, 1, 15, tzinfo=timezone.utc)
    workflow.tags = tags or {"environment": "production", "team": "platform"}

    # Default definition with HTTP trigger
    if definition is None:
        definition = {
            "triggers": {
                "manual": {
                    "type": "Request",
                    "kind": "Http",
                }
            },
            "actions": {}
        }
    workflow.definition = definition

    return workflow


def _create_mock_logic_client(
    workflows: list,
) -> MagicMock:
    """Create a mock LogicManagementClient."""
    client = MagicMock()

    # Mock workflows.list_by_subscription()
    client.workflows.list_by_subscription.return_value = workflows

    return client


# Fixtures

@pytest.fixture
def mock_azure_logic_client():
    """Return a mocked Azure Logic client with sample responses."""
    workflow = _create_mock_workflow()
    return _create_mock_logic_client(workflows=[workflow])


@pytest.fixture
def mock_azure_logic_client_http_trigger():
    """Return a mocked client with HTTP trigger workflow."""
    definition = {
        "triggers": {
            "manual": {
                "type": "Request",
                "kind": "Http",
            }
        },
        "actions": {}
    }
    workflow = _create_mock_workflow(definition=definition)
    return _create_mock_logic_client(workflows=[workflow])


@pytest.fixture
def mock_azure_logic_client_recurrence():
    """Return a mocked client with recurrence trigger workflow."""
    definition = {
        "triggers": {
            "Recurrence": {
                "type": "Recurrence",
                "recurrence": {
                    "frequency": "Day",
                    "interval": 1,
                }
            }
        },
        "actions": {}
    }
    workflow = _create_mock_workflow(definition=definition)
    return _create_mock_logic_client(workflows=[workflow])


@pytest.fixture
def mock_azure_logic_client_identity():
    """Return a mocked client with managed identity."""
    identity = MagicMock()
    identity.type = "SystemAssigned"
    identity.principal_id = "00000000-0000-0000-0000-000000000001"
    identity.tenant_id = "00000000-0000-0000-0000-000000000002"
    identity.user_assigned_identities = None

    workflow = _create_mock_workflow(identity=identity)
    return _create_mock_logic_client(workflows=[workflow])


@pytest.fixture
def mock_azure_logic_client_ise():
    """Return a mocked client with Integration Service Environment."""
    ise = MagicMock()
    ise.id = "/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Logic/integrationServiceEnvironments/test-ise"
    ise.name = "test-ise"
    ise.type = "Microsoft.Logic/integrationServiceEnvironments"

    workflow = _create_mock_workflow(ise=ise)
    return _create_mock_logic_client(workflows=[workflow])


@pytest.fixture
def mock_azure_logic_client_access_control():
    """Return a mocked client with access control configuration."""
    access_control = MagicMock()

    # Trigger access control with IP restrictions
    triggers = MagicMock()
    ip_range = MagicMock()
    ip_range.address_range = "10.0.0.0/24"
    triggers.allowed_caller_ip_addresses = [ip_range]
    triggers.open_authentication_policies = None
    access_control.triggers = triggers

    access_control.contents = None
    access_control.actions = None
    access_control.workflow_management = None

    workflow = _create_mock_workflow(access_control=access_control)
    return _create_mock_logic_client(workflows=[workflow])


@pytest.fixture
def mock_azure_logic_client_connections():
    """Return a mocked client with API connections."""
    definition = {
        "triggers": {
            "manual": {
                "type": "Request",
                "kind": "Http",
            }
        },
        "actions": {
            "Send_email": {
                "type": "ApiConnection",
                "inputs": {
                    "host": {
                        "connection": {
                            "name": "@parameters('$connections')['office365']['connectionId']"
                        }
                    }
                }
            }
        }
    }
    workflow = _create_mock_workflow(definition=definition)
    return _create_mock_logic_client(workflows=[workflow])


@pytest.fixture
def mock_azure_logic_client_integration_account():
    """Return a mocked client with integration account."""
    integration_account = MagicMock()
    integration_account.id = "/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Logic/integrationAccounts/test-account"
    integration_account.name = "test-account"
    integration_account.type = "Microsoft.Logic/integrationAccounts"

    workflow = _create_mock_workflow(integration_account=integration_account)
    return _create_mock_logic_client(workflows=[workflow])


@pytest.fixture
def mock_azure_logic_client_empty():
    """Return a mocked client with no workflows."""
    return _create_mock_logic_client(workflows=[])


@pytest.fixture
def mock_azure_logic_client_error():
    """Return a mocked client that raises an error."""
    client = MagicMock()
    client.workflows.list_by_subscription.side_effect = Exception("API Error: Access Denied")
    return client
