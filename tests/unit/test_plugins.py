"""
Tests for Plugin System.

Tests plugin discovery, loading, registration, and lifecycle management.
"""

from __future__ import annotations

import tempfile
import threading
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from stance.plugins.base import (
    Plugin,
    PluginType,
    PluginMetadata,
    PluginInfo,
    PluginError,
    PluginLoadError,
    PluginConfigError,
)
from stance.plugins.interfaces import (
    CollectorPlugin,
    PolicyPlugin,
    EnricherPlugin,
    AlertDestinationPlugin,
    ReportFormatPlugin,
)
from stance.plugins.registry import PluginRegistry, get_registry
from stance.plugins.loader import PluginLoader, discover_plugins, load_plugin
from stance.plugins.manager import PluginManager, get_plugin_manager


# =============================================================================
# Test Fixtures and Sample Plugins
# =============================================================================


class SampleCollectorPlugin(CollectorPlugin):
    """Sample collector for testing."""

    @classmethod
    def _get_collector_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="sample-collector",
            version="1.0.0",
            description="Sample collector plugin",
            author="Test Author",
            tags=["test", "sample"],
        )

    def initialize(self, config: dict[str, Any]) -> None:
        self.config = config
        self.initialized = True

    def shutdown(self) -> None:
        self.initialized = False

    def collect(self, region: str | None = None):
        from stance.models import AssetCollection
        return AssetCollection([])

    def get_supported_resource_types(self) -> list[str]:
        return ["test_resource"]


class SamplePolicyPlugin(PolicyPlugin):
    """Sample policy for testing."""

    @classmethod
    def _get_policy_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="sample-policy",
            version="1.0.0",
            description="Sample policy plugin",
        )

    def initialize(self, config: dict[str, Any]) -> None:
        self.config = config

    def shutdown(self) -> None:
        pass

    def evaluate(self, asset):
        return []

    def get_resource_types(self) -> list[str]:
        return ["test_resource"]

    def get_severity(self) -> str:
        return "medium"


class SampleEnricherPlugin(EnricherPlugin):
    """Sample enricher for testing."""

    @classmethod
    def _get_enricher_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="sample-enricher",
            version="1.0.0",
            description="Sample enricher plugin",
        )

    def initialize(self, config: dict[str, Any]) -> None:
        self.config = config

    def shutdown(self) -> None:
        pass

    def enrich_asset(self, asset):
        return asset

    def enrich_finding(self, finding, asset):
        return finding


class SampleAlertPlugin(AlertDestinationPlugin):
    """Sample alert destination for testing."""

    @classmethod
    def _get_alert_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="sample-alert",
            version="1.0.0",
            description="Sample alert plugin",
        )

    def initialize(self, config: dict[str, Any]) -> None:
        self.config = config

    def shutdown(self) -> None:
        pass

    def send_alert(self, finding, context) -> bool:
        return True

    def send_batch_alerts(self, findings, context):
        return len(findings), 0


class SampleReportPlugin(ReportFormatPlugin):
    """Sample report format for testing."""

    @classmethod
    def _get_report_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="sample-report",
            version="1.0.0",
            description="Sample report plugin",
        )

    def initialize(self, config: dict[str, Any]) -> None:
        self.config = config

    def shutdown(self) -> None:
        pass

    def get_format_name(self) -> str:
        return "sample"

    def get_file_extension(self) -> str:
        return ".txt"

    def generate_report(self, findings, assets, context) -> bytes:
        return b"Sample Report"


class ConfigurablePlugin(Plugin):
    """Plugin that validates configuration."""

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="configurable",
            version="1.0.0",
            description="Configurable plugin",
            plugin_type=PluginType.COLLECTOR,
            config_schema={
                "type": "object",
                "properties": {
                    "api_key": {"type": "string"},
                    "timeout": {"type": "integer"},
                },
                "required": ["api_key"],
            },
        )

    def initialize(self, config: dict[str, Any]) -> None:
        errors = self.validate_config(config)
        if errors:
            raise PluginConfigError(f"Invalid config: {errors}")
        self.config = config

    def shutdown(self) -> None:
        pass

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        errors = []
        if "api_key" not in config:
            errors.append("api_key is required")
        return errors


@pytest.fixture
def registry():
    """Create a fresh registry for each test."""
    reg = PluginRegistry()
    yield reg
    reg.clear()


@pytest.fixture
def temp_plugin_dir():
    """Create a temporary directory for plugins."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


# =============================================================================
# PluginType Tests
# =============================================================================


class TestPluginType:
    """Tests for PluginType enum."""

    def test_all_types_exist(self):
        """Test all plugin types are defined."""
        assert PluginType.COLLECTOR.value == "collector"
        assert PluginType.POLICY.value == "policy"
        assert PluginType.ENRICHER.value == "enricher"
        assert PluginType.ALERT_DESTINATION.value == "alert_destination"
        assert PluginType.REPORT_FORMAT.value == "report_format"

    def test_type_count(self):
        """Test expected number of types."""
        assert len(PluginType) == 5


# =============================================================================
# PluginMetadata Tests
# =============================================================================


class TestPluginMetadata:
    """Tests for PluginMetadata dataclass."""

    def test_default_values(self):
        """Test default metadata values."""
        meta = PluginMetadata(
            name="test",
            version="1.0.0",
            description="Test plugin",
        )
        assert meta.name == "test"
        assert meta.version == "1.0.0"
        assert meta.author == ""
        assert meta.plugin_type == PluginType.COLLECTOR
        assert meta.tags == []
        assert meta.dependencies == []
        assert meta.config_schema is None

    def test_to_dict(self):
        """Test dictionary conversion."""
        meta = PluginMetadata(
            name="test",
            version="1.0.0",
            description="Test plugin",
            author="Author",
            plugin_type=PluginType.POLICY,
            tags=["tag1"],
        )
        d = meta.to_dict()
        assert d["name"] == "test"
        assert d["version"] == "1.0.0"
        assert d["plugin_type"] == "policy"
        assert d["tags"] == ["tag1"]


# =============================================================================
# PluginInfo Tests
# =============================================================================


class TestPluginInfo:
    """Tests for PluginInfo dataclass."""

    def test_properties(self):
        """Test PluginInfo properties."""
        meta = PluginMetadata(
            name="test",
            version="1.0.0",
            description="Test",
            plugin_type=PluginType.ENRICHER,
        )
        info = PluginInfo(metadata=meta)

        assert info.name == "test"
        assert info.version == "1.0.0"
        assert info.plugin_type == PluginType.ENRICHER

    def test_default_values(self):
        """Test default PluginInfo values."""
        meta = PluginMetadata(name="test", version="1.0.0", description="Test")
        info = PluginInfo(metadata=meta)

        assert info.is_enabled is True
        assert info.is_loaded is False
        assert info.load_error is None
        assert info.config == {}

    def test_to_dict(self):
        """Test dictionary conversion."""
        meta = PluginMetadata(name="test", version="1.0.0", description="Test")
        info = PluginInfo(metadata=meta, is_loaded=True)
        d = info.to_dict()

        assert d["is_loaded"] is True
        assert "metadata" in d


# =============================================================================
# Plugin Base Class Tests
# =============================================================================


class TestPluginBase:
    """Tests for Plugin base class."""

    def test_sample_collector_metadata(self):
        """Test sample collector metadata."""
        meta = SampleCollectorPlugin.get_metadata()
        assert meta.name == "sample-collector"
        assert meta.plugin_type == PluginType.COLLECTOR

    def test_sample_policy_metadata(self):
        """Test sample policy metadata."""
        meta = SamplePolicyPlugin.get_metadata()
        assert meta.name == "sample-policy"
        assert meta.plugin_type == PluginType.POLICY

    def test_sample_enricher_metadata(self):
        """Test sample enricher metadata."""
        meta = SampleEnricherPlugin.get_metadata()
        assert meta.plugin_type == PluginType.ENRICHER

    def test_sample_alert_metadata(self):
        """Test sample alert metadata."""
        meta = SampleAlertPlugin.get_metadata()
        assert meta.plugin_type == PluginType.ALERT_DESTINATION

    def test_sample_report_metadata(self):
        """Test sample report metadata."""
        meta = SampleReportPlugin.get_metadata()
        assert meta.plugin_type == PluginType.REPORT_FORMAT

    def test_plugin_properties(self):
        """Test plugin instance properties."""
        plugin = SampleCollectorPlugin()
        plugin.initialize({})

        assert plugin.name == "sample-collector"
        assert plugin.version == "1.0.0"
        assert plugin.plugin_type == PluginType.COLLECTOR


# =============================================================================
# PluginRegistry Tests
# =============================================================================


class TestPluginRegistry:
    """Tests for PluginRegistry."""

    def test_register_plugin(self, registry):
        """Test registering a plugin."""
        info = registry.register(SampleCollectorPlugin)

        assert info.name == "sample-collector"
        assert info.is_loaded is True
        assert registry.plugin_count == 1

    def test_register_duplicate_fails(self, registry):
        """Test duplicate registration fails."""
        registry.register(SampleCollectorPlugin)

        with pytest.raises(PluginError):
            registry.register(SampleCollectorPlugin)

    def test_unregister_plugin(self, registry):
        """Test unregistering a plugin."""
        registry.register(SampleCollectorPlugin)
        assert registry.unregister("sample-collector") is True
        assert registry.plugin_count == 0

    def test_unregister_nonexistent(self, registry):
        """Test unregistering nonexistent plugin."""
        assert registry.unregister("nonexistent") is False

    def test_get_plugin_info(self, registry):
        """Test getting plugin info."""
        registry.register(SampleCollectorPlugin)
        info = registry.get_plugin_info("sample-collector")

        assert info is not None
        assert info.name == "sample-collector"

    def test_get_plugin_info_nonexistent(self, registry):
        """Test getting nonexistent plugin info."""
        assert registry.get_plugin_info("nonexistent") is None

    def test_get_plugin(self, registry):
        """Test getting plugin instance."""
        registry.register(SampleCollectorPlugin)
        plugin = registry.get_plugin("sample-collector")

        assert plugin is not None
        assert isinstance(plugin, SampleCollectorPlugin)

    def test_get_plugin_typed(self, registry):
        """Test getting typed plugin instance."""
        registry.register(SampleCollectorPlugin)
        plugin = registry.get_plugin_typed("sample-collector", CollectorPlugin)

        assert plugin is not None
        assert isinstance(plugin, CollectorPlugin)

    def test_get_plugin_typed_wrong_type(self, registry):
        """Test getting plugin with wrong type returns None."""
        registry.register(SampleCollectorPlugin)
        plugin = registry.get_plugin_typed("sample-collector", PolicyPlugin)

        assert plugin is None

    def test_list_plugins(self, registry):
        """Test listing all plugins."""
        registry.register(SampleCollectorPlugin)
        registry.register(SamplePolicyPlugin)

        plugins = registry.list_plugins()
        assert len(plugins) == 2

    def test_list_plugins_by_type(self, registry):
        """Test listing plugins by type."""
        registry.register(SampleCollectorPlugin)
        registry.register(SamplePolicyPlugin)

        collectors = registry.list_plugins(plugin_type=PluginType.COLLECTOR)
        assert len(collectors) == 1
        assert collectors[0].name == "sample-collector"

    def test_list_plugins_enabled_only(self, registry):
        """Test listing only enabled plugins."""
        registry.register(SampleCollectorPlugin)
        registry.register(SamplePolicyPlugin)
        registry.disable_plugin("sample-policy")

        enabled = registry.list_plugins(enabled_only=True)
        assert len(enabled) == 1

    def test_list_plugins_loaded_only(self, registry):
        """Test listing only loaded plugins."""
        registry.register(SampleCollectorPlugin)
        plugins = registry.list_plugins(loaded_only=True)
        assert len(plugins) == 1

    def test_list_plugins_by_type_instances(self, registry):
        """Test listing plugin instances by type."""
        registry.register(SampleCollectorPlugin)
        registry.register(SamplePolicyPlugin)

        instances = registry.list_plugins_by_type(PluginType.COLLECTOR)
        assert len(instances) == 1
        assert isinstance(instances[0], SampleCollectorPlugin)

    def test_enable_disable_plugin(self, registry):
        """Test enabling and disabling plugins."""
        registry.register(SampleCollectorPlugin)

        assert registry.disable_plugin("sample-collector") is True
        info = registry.get_plugin_info("sample-collector")
        assert info.is_enabled is False

        assert registry.enable_plugin("sample-collector") is True
        info = registry.get_plugin_info("sample-collector")
        assert info.is_enabled is True

    def test_configure_plugin(self, registry):
        """Test configuring a plugin."""
        registry.register(SampleCollectorPlugin)
        config = {"key": "value"}

        assert registry.configure_plugin("sample-collector", config) is True
        info = registry.get_plugin_info("sample-collector")
        assert info.config == config

    def test_configure_with_validation(self, registry):
        """Test configuration with validation."""
        registry.register(ConfigurablePlugin, config={"api_key": "test"})

        # Invalid config should fail
        assert registry.configure_plugin("configurable", {}) is False

        # Valid config should succeed
        assert registry.configure_plugin("configurable", {"api_key": "new"}) is True

    def test_clear_registry(self, registry):
        """Test clearing the registry."""
        registry.register(SampleCollectorPlugin)
        registry.register(SamplePolicyPlugin)

        registry.clear()
        assert registry.plugin_count == 0
        assert registry.loaded_count == 0

    def test_thread_safety(self, registry):
        """Test thread-safe operations."""
        errors = []

        def register_plugins():
            try:
                for i in range(10):
                    try:
                        registry.register(SampleCollectorPlugin)
                    except PluginError:
                        pass  # Duplicate registration is expected
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=register_plugins) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []


# =============================================================================
# PluginLoader Tests
# =============================================================================


class TestPluginLoader:
    """Tests for PluginLoader."""

    def test_load_plugin_class(self, registry):
        """Test loading plugin from class."""
        loader = PluginLoader(registry=registry)
        info = loader.load_plugin_class(SampleCollectorPlugin)

        assert info.name == "sample-collector"
        assert info.is_loaded is True

    def test_load_plugin_with_config(self, registry):
        """Test loading plugin with configuration."""
        loader = PluginLoader(registry=registry)
        config = {"key": "value"}
        info = loader.load_plugin_class(SampleCollectorPlugin, config=config)

        assert info.config == config

    def test_discover_in_empty_dir(self, temp_plugin_dir):
        """Test discovery in empty directory."""
        loader = PluginLoader(plugin_dirs=[str(temp_plugin_dir)])
        discovered = loader.discover_plugins()

        # May find plugins in default dir too
        assert isinstance(discovered, list)

    def test_discover_python_files(self, temp_plugin_dir):
        """Test discovering Python plugin files."""
        # Create a sample plugin file
        plugin_file = temp_plugin_dir / "my_plugin.py"
        plugin_file.write_text("""
from stance.plugins.base import Plugin, PluginMetadata, PluginType

class MyPlugin(Plugin):
    @classmethod
    def get_metadata(cls):
        return PluginMetadata(
            name="my-plugin",
            version="1.0.0",
            description="Test plugin",
            plugin_type=PluginType.COLLECTOR,
        )

    def initialize(self, config):
        pass

    def shutdown(self):
        pass
""")

        loader = PluginLoader(plugin_dirs=[str(temp_plugin_dir)])
        discovered = loader._discover_in_directory(temp_plugin_dir)

        assert str(plugin_file) in discovered

    def test_load_plugin_from_file(self, temp_plugin_dir, registry):
        """Test loading plugin from file."""
        # Create a sample plugin file
        plugin_file = temp_plugin_dir / "file_plugin.py"
        plugin_file.write_text("""
from stance.plugins.base import Plugin, PluginMetadata, PluginType

class FilePlugin(Plugin):
    @classmethod
    def get_metadata(cls):
        return PluginMetadata(
            name="file-plugin",
            version="1.0.0",
            description="File plugin",
            plugin_type=PluginType.COLLECTOR,
        )

    def initialize(self, config):
        self.config = config

    def shutdown(self):
        pass
""")

        loader = PluginLoader(registry=registry, plugin_dirs=[str(temp_plugin_dir)])
        info = loader.load_plugin_from_file(str(plugin_file))

        assert info.name == "file-plugin"
        assert info.is_loaded is True

    def test_load_plugin_from_nonexistent_file(self, registry):
        """Test loading from nonexistent file."""
        loader = PluginLoader(registry=registry)

        with pytest.raises(PluginLoadError):
            loader.load_plugin_from_file("/nonexistent/path.py")

    def test_load_plugin_no_class_found(self, temp_plugin_dir, registry):
        """Test loading file with no Plugin class."""
        plugin_file = temp_plugin_dir / "no_plugin.py"
        plugin_file.write_text("# Just a comment")

        loader = PluginLoader(registry=registry)

        with pytest.raises(PluginLoadError, match="No Plugin subclass found"):
            loader.load_plugin_from_file(str(plugin_file))


# =============================================================================
# PluginManager Tests
# =============================================================================


class TestPluginManager:
    """Tests for PluginManager."""

    def test_manager_init(self, registry, temp_plugin_dir):
        """Test manager initialization."""
        config_file = temp_plugin_dir / "plugins.json"
        manager = PluginManager(
            registry=registry,
            config_path=config_file,
            auto_discover=False,
        )

        assert manager.plugin_count == 0

    def test_load_plugin(self, registry, temp_plugin_dir):
        """Test loading a plugin through manager."""
        config_file = temp_plugin_dir / "plugins.json"
        manager = PluginManager(
            registry=registry,
            config_path=config_file,
            auto_discover=False,
        )

        info = manager.load_plugin(SampleCollectorPlugin)
        assert info.name == "sample-collector"
        assert manager.plugin_count == 1

    def test_unload_plugin(self, registry, temp_plugin_dir):
        """Test unloading a plugin."""
        config_file = temp_plugin_dir / "plugins.json"
        manager = PluginManager(
            registry=registry,
            config_path=config_file,
            auto_discover=False,
        )

        manager.load_plugin(SampleCollectorPlugin)
        assert manager.unload_plugin("sample-collector") is True
        assert manager.plugin_count == 0

    def test_get_plugin(self, registry, temp_plugin_dir):
        """Test getting a plugin."""
        config_file = temp_plugin_dir / "plugins.json"
        manager = PluginManager(
            registry=registry,
            config_path=config_file,
            auto_discover=False,
        )

        manager.load_plugin(SampleCollectorPlugin)
        plugin = manager.get_plugin("sample-collector")

        assert plugin is not None
        assert isinstance(plugin, SampleCollectorPlugin)

    def test_list_plugins(self, registry, temp_plugin_dir):
        """Test listing plugins."""
        config_file = temp_plugin_dir / "plugins.json"
        manager = PluginManager(
            registry=registry,
            config_path=config_file,
            auto_discover=False,
        )

        manager.load_plugin(SampleCollectorPlugin)
        manager.load_plugin(SamplePolicyPlugin)

        plugins = manager.list_plugins()
        assert len(plugins) == 2

    def test_get_collectors(self, registry, temp_plugin_dir):
        """Test getting collectors."""
        config_file = temp_plugin_dir / "plugins.json"
        manager = PluginManager(
            registry=registry,
            config_path=config_file,
            auto_discover=False,
        )

        manager.load_plugin(SampleCollectorPlugin)
        manager.load_plugin(SamplePolicyPlugin)

        collectors = manager.get_collectors()
        assert len(collectors) == 1
        assert isinstance(collectors[0], CollectorPlugin)

    def test_get_policies(self, registry, temp_plugin_dir):
        """Test getting policies."""
        config_file = temp_plugin_dir / "plugins.json"
        manager = PluginManager(
            registry=registry,
            config_path=config_file,
            auto_discover=False,
        )

        manager.load_plugin(SamplePolicyPlugin)
        policies = manager.get_policies()

        assert len(policies) == 1
        assert isinstance(policies[0], PolicyPlugin)

    def test_get_enrichers(self, registry, temp_plugin_dir):
        """Test getting enrichers."""
        config_file = temp_plugin_dir / "plugins.json"
        manager = PluginManager(
            registry=registry,
            config_path=config_file,
            auto_discover=False,
        )

        manager.load_plugin(SampleEnricherPlugin)
        enrichers = manager.get_enrichers()

        assert len(enrichers) == 1
        assert isinstance(enrichers[0], EnricherPlugin)

    def test_get_alert_destinations(self, registry, temp_plugin_dir):
        """Test getting alert destinations."""
        config_file = temp_plugin_dir / "plugins.json"
        manager = PluginManager(
            registry=registry,
            config_path=config_file,
            auto_discover=False,
        )

        manager.load_plugin(SampleAlertPlugin)
        alerts = manager.get_alert_destinations()

        assert len(alerts) == 1
        assert isinstance(alerts[0], AlertDestinationPlugin)

    def test_get_report_formats(self, registry, temp_plugin_dir):
        """Test getting report formats."""
        config_file = temp_plugin_dir / "plugins.json"
        manager = PluginManager(
            registry=registry,
            config_path=config_file,
            auto_discover=False,
        )

        manager.load_plugin(SampleReportPlugin)
        reports = manager.get_report_formats()

        assert len(reports) == 1
        assert isinstance(reports[0], ReportFormatPlugin)

    def test_configure_plugin(self, registry, temp_plugin_dir):
        """Test configuring a plugin."""
        config_file = temp_plugin_dir / "plugins.json"
        manager = PluginManager(
            registry=registry,
            config_path=config_file,
            auto_discover=False,
        )

        manager.load_plugin(SampleCollectorPlugin)
        config = {"key": "value"}

        assert manager.configure_plugin("sample-collector", config) is True
        info = manager.get_plugin_info("sample-collector")
        assert info.config == config

    def test_enable_disable(self, registry, temp_plugin_dir):
        """Test enabling and disabling plugins."""
        config_file = temp_plugin_dir / "plugins.json"
        manager = PluginManager(
            registry=registry,
            config_path=config_file,
            auto_discover=False,
        )

        manager.load_plugin(SampleCollectorPlugin)

        assert manager.disable_plugin("sample-collector") is True
        info = manager.get_plugin_info("sample-collector")
        assert info.is_enabled is False

        assert manager.enable_plugin("sample-collector") is True
        info = manager.get_plugin_info("sample-collector")
        assert info.is_enabled is True

    def test_shutdown(self, registry, temp_plugin_dir):
        """Test manager shutdown."""
        config_file = temp_plugin_dir / "plugins.json"
        manager = PluginManager(
            registry=registry,
            config_path=config_file,
            auto_discover=False,
        )

        manager.load_plugin(SampleCollectorPlugin)
        manager.shutdown()

        assert manager.plugin_count == 0

    def test_config_persistence(self, registry, temp_plugin_dir):
        """Test configuration persistence."""
        config_file = temp_plugin_dir / "plugins.json"
        manager = PluginManager(
            registry=registry,
            config_path=config_file,
            auto_discover=False,
        )

        manager.load_plugin(SampleCollectorPlugin, config={"key": "value"})

        # Config should be saved
        assert config_file.exists()


# =============================================================================
# Helper Function Tests
# =============================================================================


class TestHelperFunctions:
    """Tests for module-level helper functions."""

    def test_discover_plugins(self, temp_plugin_dir):
        """Test discover_plugins function."""
        discovered = discover_plugins(plugin_dirs=[str(temp_plugin_dir)])
        assert isinstance(discovered, list)

    def test_load_plugin_from_class(self):
        """Test load_plugin with class."""
        registry = PluginRegistry()
        info = load_plugin(SampleCollectorPlugin, registry=registry)

        assert info.name == "sample-collector"
        registry.clear()

    def test_load_plugin_from_file(self, temp_plugin_dir):
        """Test load_plugin with file path."""
        plugin_file = temp_plugin_dir / "helper_plugin.py"
        plugin_file.write_text("""
from stance.plugins.base import Plugin, PluginMetadata, PluginType

class HelperPlugin(Plugin):
    @classmethod
    def get_metadata(cls):
        return PluginMetadata(
            name="helper-plugin",
            version="1.0.0",
            description="Helper test",
            plugin_type=PluginType.COLLECTOR,
        )

    def initialize(self, config):
        pass

    def shutdown(self):
        pass
""")

        registry = PluginRegistry()
        info = load_plugin(str(plugin_file), registry=registry)

        assert info.name == "helper-plugin"
        registry.clear()


# =============================================================================
# Plugin Interface Tests
# =============================================================================


class TestPluginInterfaces:
    """Tests for specific plugin interface methods."""

    def test_collector_interface(self):
        """Test collector plugin interface."""
        plugin = SampleCollectorPlugin()
        plugin.initialize({})

        assert plugin.get_supported_resource_types() == ["test_resource"]
        result = plugin.collect()
        assert hasattr(result, "__iter__")

    def test_policy_interface(self):
        """Test policy plugin interface."""
        plugin = SamplePolicyPlugin()
        plugin.initialize({})

        assert plugin.get_resource_types() == ["test_resource"]
        assert plugin.get_severity() == "medium"

    def test_enricher_interface(self):
        """Test enricher plugin interface."""
        plugin = SampleEnricherPlugin()
        plugin.initialize({})

        # Should return empty list for all types
        assert plugin.get_supported_resource_types() == []

    def test_alert_interface(self):
        """Test alert destination interface."""
        plugin = SampleAlertPlugin()
        plugin.initialize({})

        # Test connection should work
        success, message = plugin.test_connection()
        assert isinstance(success, bool)

    def test_report_interface(self):
        """Test report format interface."""
        plugin = SampleReportPlugin()
        plugin.initialize({})

        assert plugin.get_format_name() == "sample"
        assert plugin.get_file_extension() == ".txt"
        assert plugin.get_mime_type() == "application/octet-stream"
