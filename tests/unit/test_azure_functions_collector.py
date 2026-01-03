"""
Unit tests for AzureFunctionsCollector.

Tests cover:
- Azure Function App collection with mocked Azure SDK responses
- Runtime deprecation detection
- HTTPS-only configuration
- Authentication settings
- Network exposure detection (IP restrictions, VNet integration)
- Managed identity configuration
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
mock_azure_web = MagicMock()
mock_azure_identity = MagicMock()

sys.modules["azure"] = MagicMock()
sys.modules["azure.mgmt"] = MagicMock()
sys.modules["azure.mgmt.web"] = mock_azure_web
sys.modules["azure.identity"] = mock_azure_identity


class TestAzureFunctionsCollector:
    """Tests for AzureFunctionsCollector."""

    def test_azure_functions_collector_init(self):
        """Test AzureFunctionsCollector can be initialized."""
        import importlib
        import stance.collectors.azure_functions as azure_functions_module
        importlib.reload(azure_functions_module)

        collector = azure_functions_module.AzureFunctionsCollector(
            subscription_id="test-subscription-id"
        )
        assert collector.collector_name == "azure_functions"
        assert collector.subscription_id == "test-subscription-id"
        assert "azure_function_app" in collector.resource_types

    def test_azure_functions_collector_collect_function_apps(
        self, mock_azure_web_client
    ):
        """Test Function App collection with mock response."""
        import importlib
        import stance.collectors.azure_functions as azure_functions_module
        importlib.reload(azure_functions_module)

        collector = azure_functions_module.AzureFunctionsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_web_client", return_value=mock_azure_web_client
        ):
            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            assert len(assets) == 1

            func_app = assets[0]
            assert func_app.name == "test-function-app"
            assert func_app.resource_type == "azure_function_app"
            assert func_app.cloud_provider == "azure"
            assert func_app.account_id == "test-subscription-id"
            assert func_app.region == "eastus"

    def test_azure_functions_collector_https_only(
        self, mock_azure_web_client_https
    ):
        """Test Function App with HTTPS only enabled."""
        import importlib
        import stance.collectors.azure_functions as azure_functions_module
        importlib.reload(azure_functions_module)

        collector = azure_functions_module.AzureFunctionsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_web_client", return_value=mock_azure_web_client_https
        ):
            assets = collector.collect()

            assert len(assets) == 1
            func_app = assets[0]
            assert func_app.raw_config["https_only"] is True

    def test_azure_functions_collector_managed_identity(
        self, mock_azure_web_client_identity
    ):
        """Test Function App with managed identity."""
        import importlib
        import stance.collectors.azure_functions as azure_functions_module
        importlib.reload(azure_functions_module)

        collector = azure_functions_module.AzureFunctionsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_web_client", return_value=mock_azure_web_client_identity
        ):
            assets = collector.collect()

            assert len(assets) == 1
            func_app = assets[0]
            assert func_app.raw_config["has_managed_identity"] is True
            assert func_app.raw_config["uses_system_assigned_identity"] is True

    def test_azure_functions_collector_vnet_integration(
        self, mock_azure_web_client_vnet
    ):
        """Test Function App with VNet integration."""
        import importlib
        import stance.collectors.azure_functions as azure_functions_module
        importlib.reload(azure_functions_module)

        collector = azure_functions_module.AzureFunctionsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_web_client", return_value=mock_azure_web_client_vnet
        ):
            assets = collector.collect()

            assert len(assets) == 1
            func_app = assets[0]
            assert func_app.raw_config["has_vnet_integration"] is True

    def test_azure_functions_collector_ip_restrictions(
        self, mock_azure_web_client_restricted
    ):
        """Test Function App with IP restrictions."""
        import importlib
        import stance.collectors.azure_functions as azure_functions_module
        importlib.reload(azure_functions_module)

        collector = azure_functions_module.AzureFunctionsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_web_client", return_value=mock_azure_web_client_restricted
        ):
            assets = collector.collect()

            assert len(assets) == 1
            func_app = assets[0]
            assert func_app.raw_config["has_ip_restrictions"] is True
            assert func_app.network_exposure == NETWORK_EXPOSURE_INTERNAL

    def test_azure_functions_collector_deprecated_runtime(
        self, mock_azure_web_client_deprecated
    ):
        """Test detection of deprecated runtime."""
        import importlib
        import stance.collectors.azure_functions as azure_functions_module
        importlib.reload(azure_functions_module)

        collector = azure_functions_module.AzureFunctionsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_web_client", return_value=mock_azure_web_client_deprecated
        ):
            assets = collector.collect()

            assert len(assets) == 1
            func_app = assets[0]
            assert func_app.raw_config["runtime_deprecated"] is True

    def test_azure_functions_collector_tls_version(
        self, mock_azure_web_client_tls
    ):
        """Test TLS version configuration detection."""
        import importlib
        import stance.collectors.azure_functions as azure_functions_module
        importlib.reload(azure_functions_module)

        collector = azure_functions_module.AzureFunctionsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_web_client", return_value=mock_azure_web_client_tls
        ):
            assets = collector.collect()

            assert len(assets) == 1
            func_app = assets[0]
            assert func_app.raw_config["min_tls_version"] == "1.2"
            assert func_app.raw_config["uses_tls_1_2"] is True

    def test_azure_functions_collector_auth_enabled(
        self, mock_azure_web_client_auth
    ):
        """Test authentication configuration detection."""
        import importlib
        import stance.collectors.azure_functions as azure_functions_module
        importlib.reload(azure_functions_module)

        collector = azure_functions_module.AzureFunctionsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_web_client", return_value=mock_azure_web_client_auth
        ):
            assets = collector.collect()

            assert len(assets) == 1
            func_app = assets[0]
            assert func_app.raw_config["auth_enabled"] is True

    def test_azure_functions_collector_handles_empty_response(
        self, mock_azure_web_client_empty
    ):
        """Test handling of empty Function App list."""
        import importlib
        import stance.collectors.azure_functions as azure_functions_module
        importlib.reload(azure_functions_module)

        collector = azure_functions_module.AzureFunctionsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_web_client", return_value=mock_azure_web_client_empty
        ):
            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            assert len(assets) == 0

    def test_azure_functions_collector_handles_api_error(
        self, mock_azure_web_client_error
    ):
        """Test graceful handling of API errors."""
        import importlib
        import stance.collectors.azure_functions as azure_functions_module
        importlib.reload(azure_functions_module)

        collector = azure_functions_module.AzureFunctionsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_web_client", return_value=mock_azure_web_client_error
        ):
            # Should not raise, but return empty collection
            assets = collector.collect()
            assert isinstance(assets, AssetCollection)
            assert len(assets) == 0

    def test_azure_functions_collector_filters_function_apps_only(
        self, mock_azure_web_client_mixed
    ):
        """Test that only Function Apps are collected, not regular web apps."""
        import importlib
        import stance.collectors.azure_functions as azure_functions_module
        importlib.reload(azure_functions_module)

        collector = azure_functions_module.AzureFunctionsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_web_client", return_value=mock_azure_web_client_mixed
        ):
            assets = collector.collect()

            # Should only get the function app, not the regular web app
            assert len(assets) == 1
            assert assets[0].name == "test-function-app"

    def test_azure_functions_collector_tags_extraction(
        self, mock_azure_web_client
    ):
        """Test that tags are extracted correctly."""
        import importlib
        import stance.collectors.azure_functions as azure_functions_module
        importlib.reload(azure_functions_module)

        collector = azure_functions_module.AzureFunctionsCollector(
            subscription_id="test-subscription-id"
        )

        with patch.object(
            collector, "_get_web_client", return_value=mock_azure_web_client
        ):
            assets = collector.collect()

            assert len(assets) == 1
            func_app = assets[0]
            assert func_app.tags == {"environment": "production", "team": "platform"}


# Helper functions to create mock objects

def _create_mock_function_app(
    name: str = "test-function-app",
    location: str = "eastus",
    kind: str = "functionapp,linux",
    https_only: bool = False,
    identity: MagicMock | None = None,
    vnet_subnet_id: str | None = None,
    tags: dict | None = None,
) -> MagicMock:
    """Create a mock Function App object."""
    app = MagicMock()
    app.id = f"/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Web/sites/{name}"
    app.name = name
    app.location = location
    app.kind = kind
    app.state = "Running"
    app.default_host_name = f"{name}.azurewebsites.net"
    app.enabled = True
    app.host_names = [f"{name}.azurewebsites.net"]
    app.host_name_ssl_states = []
    app.repository_site_name = name
    app.usage_state = "Normal"
    app.availability_state = "Normal"
    app.last_modified_time_utc = datetime(2024, 1, 1, tzinfo=timezone.utc)
    app.https_only = https_only
    app.client_cert_enabled = False
    app.client_cert_mode = None
    app.identity = identity
    app.virtual_network_subnet_id = vnet_subnet_id
    app.tags = tags or {"environment": "production", "team": "platform"}
    return app


def _create_mock_site_config(
    min_tls_version: str = "1.2",
    functions_runtime_version: str = "~4",
    linux_fx_version: str = "PYTHON|3.11",
    remote_debugging_enabled: bool = False,
    cors_allowed_origins: list | None = None,
    ip_restrictions: list | None = None,
) -> MagicMock:
    """Create a mock site configuration object."""
    config = MagicMock()
    config.net_framework_version = None
    config.php_version = None
    config.python_version = None
    config.node_version = None
    config.java_version = None
    config.java_container = None
    config.java_container_version = None
    config.power_shell_version = None
    config.linux_fx_version = linux_fx_version
    config.windows_fx_version = None
    config.http20_enabled = True
    config.min_tls_version = min_tls_version
    config.ftps_state = "Disabled"
    config.remote_debugging_enabled = remote_debugging_enabled
    config.remote_debugging_version = None

    # CORS
    if cors_allowed_origins is not None:
        cors = MagicMock()
        cors.allowed_origins = cors_allowed_origins
        cors.support_credentials = False
        config.cors = cors
    else:
        config.cors = None

    config.always_on = True
    config.web_sockets_enabled = False
    config.managed_pipeline_mode = "Integrated"
    config.local_my_sql_enabled = False
    config.api_definition = None
    config.api_management_config = None
    config.auto_heal_enabled = False
    config.app_command_line = None
    config.scm_type = "None"
    config.scm_min_tls_version = "1.2"
    config.use_32_bit_worker_process = False
    config.vnet_route_all_enabled = False

    # App settings
    runtime_setting = MagicMock()
    runtime_setting.name = "FUNCTIONS_EXTENSION_VERSION"
    runtime_setting.value = functions_runtime_version
    config.app_settings = [runtime_setting]

    # IP restrictions
    config.ip_security_restrictions = ip_restrictions or []

    return config


def _create_mock_web_client(
    apps: list,
    site_config: MagicMock | None = None,
    auth_enabled: bool = False,
    app_settings: dict | None = None,
    connection_strings: dict | None = None,
    functions: list | None = None,
) -> MagicMock:
    """Create a mock WebSiteManagementClient."""
    client = MagicMock()

    # Mock web_apps.list()
    client.web_apps.list.return_value = apps

    # Mock web_apps.get_configuration()
    if site_config is None:
        site_config = _create_mock_site_config()
    client.web_apps.get_configuration.return_value = site_config

    # Mock auth settings v2
    auth_v2 = MagicMock()
    if auth_enabled:
        auth_v2.global_validation = MagicMock()
        auth_v2.global_validation.require_authentication = True
        auth_v2.global_validation.unauthenticated_client_action = "RedirectToLoginPage"
        auth_v2.platform = MagicMock()
        auth_v2.platform.enabled = True
        auth_v2.platform.runtime_version = "~1"
        auth_v2.identity_providers = MagicMock()
        auth_v2.identity_providers.azure_active_directory = MagicMock()
        auth_v2.identity_providers.facebook = None
        auth_v2.identity_providers.git_hub = None
        auth_v2.identity_providers.google = None
        auth_v2.identity_providers.twitter = None
        auth_v2.identity_providers.apple = None
        auth_v2.identity_providers.custom_open_id_connect_providers = None
    else:
        auth_v2.global_validation = None
        auth_v2.platform = None
        auth_v2.identity_providers = None
    client.web_apps.get_auth_settings_v2.return_value = auth_v2

    # Mock app settings
    settings = MagicMock()
    settings.properties = app_settings or {"FUNCTIONS_WORKER_RUNTIME": "python"}
    client.web_apps.list_application_settings.return_value = settings

    # Mock connection strings
    conn_strings = MagicMock()
    conn_strings.properties = connection_strings or {}
    client.web_apps.list_connection_strings.return_value = conn_strings

    # Mock functions list
    client.web_apps.list_functions.return_value = functions or []

    return client


# Fixtures

@pytest.fixture
def mock_azure_web_client():
    """Return a mocked Azure Web client with sample responses."""
    app = _create_mock_function_app()
    return _create_mock_web_client(apps=[app])


@pytest.fixture
def mock_azure_web_client_https():
    """Return a mocked client with HTTPS-only Function App."""
    app = _create_mock_function_app(https_only=True)
    return _create_mock_web_client(apps=[app])


@pytest.fixture
def mock_azure_web_client_identity():
    """Return a mocked client with managed identity."""
    identity = MagicMock()
    identity.type = "SystemAssigned"
    identity.principal_id = "00000000-0000-0000-0000-000000000001"
    identity.tenant_id = "00000000-0000-0000-0000-000000000002"
    identity.user_assigned_identities = None

    app = _create_mock_function_app(identity=identity)
    return _create_mock_web_client(apps=[app])


@pytest.fixture
def mock_azure_web_client_vnet():
    """Return a mocked client with VNet integration."""
    app = _create_mock_function_app(
        vnet_subnet_id="/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/functions"
    )
    return _create_mock_web_client(apps=[app])


@pytest.fixture
def mock_azure_web_client_restricted():
    """Return a mocked client with IP restrictions."""
    ip_rule = MagicMock()
    ip_rule.name = "AllowVNet"
    ip_rule.ip_address = None
    ip_rule.subnet_mask = None
    ip_rule.vnet_subnet_resource_id = "/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/default"
    ip_rule.vnet_traffic_tag = None
    ip_rule.subnet_traffic_tag = None
    ip_rule.action = "Allow"
    ip_rule.tag = None
    ip_rule.priority = 100
    ip_rule.headers = None

    site_config = _create_mock_site_config(ip_restrictions=[ip_rule])
    app = _create_mock_function_app()
    return _create_mock_web_client(apps=[app], site_config=site_config)


@pytest.fixture
def mock_azure_web_client_deprecated():
    """Return a mocked client with deprecated runtime."""
    site_config = _create_mock_site_config(
        functions_runtime_version="~2",
        linux_fx_version="PYTHON|3.7",
    )
    app = _create_mock_function_app()
    return _create_mock_web_client(apps=[app], site_config=site_config)


@pytest.fixture
def mock_azure_web_client_tls():
    """Return a mocked client with TLS 1.2."""
    site_config = _create_mock_site_config(min_tls_version="1.2")
    app = _create_mock_function_app()
    return _create_mock_web_client(apps=[app], site_config=site_config)


@pytest.fixture
def mock_azure_web_client_auth():
    """Return a mocked client with authentication enabled."""
    app = _create_mock_function_app()
    return _create_mock_web_client(apps=[app], auth_enabled=True)


@pytest.fixture
def mock_azure_web_client_empty():
    """Return a mocked client with no Function Apps."""
    return _create_mock_web_client(apps=[])


@pytest.fixture
def mock_azure_web_client_error():
    """Return a mocked client that raises an error."""
    client = MagicMock()
    client.web_apps.list.side_effect = Exception("API Error: Access Denied")
    return client


@pytest.fixture
def mock_azure_web_client_mixed():
    """Return a mocked client with mixed app types (function app and regular web app)."""
    function_app = _create_mock_function_app(name="test-function-app", kind="functionapp,linux")
    web_app = _create_mock_function_app(name="test-web-app", kind="app,linux")
    return _create_mock_web_client(apps=[function_app, web_app])
