"""
Plugin manager for Mantissa Stance.

Provides high-level plugin lifecycle management and coordination.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, TypeVar

from stance.plugins.base import (
    Plugin,
    PluginType,
    PluginInfo,
    PluginError,
)
from stance.plugins.interfaces import (
    CollectorPlugin,
    PolicyPlugin,
    EnricherPlugin,
    AlertDestinationPlugin,
    ReportFormatPlugin,
)
from stance.plugins.registry import PluginRegistry, get_registry
from stance.plugins.loader import PluginLoader

T = TypeVar("T", bound=Plugin)


class PluginManager:
    """
    High-level manager for plugin lifecycle.

    Coordinates plugin loading, configuration, and access
    with support for persistence and hot-reloading.
    """

    def __init__(
        self,
        registry: PluginRegistry | None = None,
        config_path: str | Path | None = None,
        auto_discover: bool = True,
    ):
        """
        Initialize the plugin manager.

        Args:
            registry: Plugin registry to use
            config_path: Path to plugin configuration file
            auto_discover: Automatically discover plugins on init
        """
        self._registry = registry or get_registry()
        self._loader = PluginLoader(registry=self._registry)
        self._config_path = Path(config_path) if config_path else self._default_config_path()
        self._configs: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._initialized = False

        # Load configuration
        self._load_config()

        # Auto-discover if enabled
        if auto_discover:
            self.discover_and_load()

        self._initialized = True

    def _default_config_path(self) -> Path:
        """Get the default plugin configuration path."""
        config_dir = os.environ.get("STANCE_CONFIG_DIR")
        if config_dir:
            return Path(config_dir) / "plugins.json"
        return Path.home() / ".stance" / "plugins.json"

    def _load_config(self) -> None:
        """Load plugin configuration from file."""
        if self._config_path.exists():
            try:
                with open(self._config_path, "r") as f:
                    data = json.load(f)
                    self._configs = data.get("plugins", {})
            except Exception:
                pass

    def _save_config(self) -> None:
        """Save plugin configuration to file."""
        try:
            self._config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._config_path, "w") as f:
                json.dump({"plugins": self._configs}, f, indent=2)
        except Exception:
            pass

    def discover_and_load(self) -> list[PluginInfo]:
        """
        Discover and load all available plugins.

        Returns:
            List of PluginInfo for loaded plugins
        """
        with self._lock:
            results = []

            # Load from directories
            discovered = self._loader.discover_plugins()
            for path in discovered:
                try:
                    plugin_name = Path(path).stem
                    config = self._configs.get(plugin_name, {})
                    info = self._loader.load_plugin_from_file(path, config)
                    results.append(info)
                except Exception:
                    pass

            # Load from entry points
            try:
                ep_results = self._loader.load_from_entry_points()
                results.extend(ep_results)
            except Exception:
                pass

            return results

    def load_plugin(
        self,
        source: str | type[Plugin],
        config: dict[str, Any] | None = None,
    ) -> PluginInfo:
        """
        Load a plugin from a source.

        Args:
            source: File path, module name, or Plugin class
            config: Plugin configuration

        Returns:
            PluginInfo for the loaded plugin
        """
        with self._lock:
            if isinstance(source, str):
                path = Path(source)
                if path.exists():
                    info = self._loader.load_plugin_from_file(source, config)
                else:
                    info = self._loader.load_plugin_from_module(source, config)
            else:
                info = self._loader.load_plugin_class(source, config)

            # Store configuration
            if config:
                self._configs[info.name] = config
                self._save_config()

            return info

    def unload_plugin(self, plugin_name: str) -> bool:
        """
        Unload a plugin.

        Args:
            plugin_name: Name of plugin to unload

        Returns:
            True if plugin was unloaded
        """
        with self._lock:
            return self._registry.unregister(plugin_name)

    def reload_plugin(self, plugin_name: str) -> PluginInfo | None:
        """
        Reload a plugin.

        Args:
            plugin_name: Name of plugin to reload

        Returns:
            New PluginInfo or None if reload failed
        """
        with self._lock:
            info = self._registry.get_plugin_info(plugin_name)
            if not info:
                return None

            module_path = info.module_path
            config = info.config

            # Unload first
            self._registry.unregister(plugin_name)

            # Try to reload
            try:
                if module_path.endswith(".py") or "/" in module_path:
                    return self._loader.load_plugin_from_file(module_path, config)
                else:
                    return self._loader.load_plugin_from_module(module_path, config)
            except Exception:
                return None

    def configure_plugin(
        self,
        plugin_name: str,
        config: dict[str, Any],
    ) -> bool:
        """
        Configure a plugin.

        Args:
            plugin_name: Name of plugin to configure
            config: New configuration

        Returns:
            True if configuration was applied
        """
        with self._lock:
            if self._registry.configure_plugin(plugin_name, config):
                self._configs[plugin_name] = config
                self._save_config()
                return True
            return False

    def get_plugin(self, plugin_name: str) -> Plugin | None:
        """
        Get a plugin instance.

        Args:
            plugin_name: Name of the plugin

        Returns:
            Plugin instance or None
        """
        return self._registry.get_plugin(plugin_name)

    def get_plugin_info(self, plugin_name: str) -> PluginInfo | None:
        """
        Get plugin information.

        Args:
            plugin_name: Name of the plugin

        Returns:
            PluginInfo or None
        """
        return self._registry.get_plugin_info(plugin_name)

    def list_plugins(
        self,
        plugin_type: PluginType | None = None,
        enabled_only: bool = False,
    ) -> list[PluginInfo]:
        """
        List registered plugins.

        Args:
            plugin_type: Filter by type
            enabled_only: Only enabled plugins

        Returns:
            List of PluginInfo
        """
        return self._registry.list_plugins(
            plugin_type=plugin_type,
            enabled_only=enabled_only,
        )

    # Type-specific accessors

    def get_collectors(self) -> list[CollectorPlugin]:
        """Get all loaded collector plugins."""
        plugins = self._registry.list_plugins_by_type(PluginType.COLLECTOR)
        return [p for p in plugins if isinstance(p, CollectorPlugin)]

    def get_policies(self) -> list[PolicyPlugin]:
        """Get all loaded policy plugins."""
        plugins = self._registry.list_plugins_by_type(PluginType.POLICY)
        return [p for p in plugins if isinstance(p, PolicyPlugin)]

    def get_enrichers(self) -> list[EnricherPlugin]:
        """Get all loaded enricher plugins."""
        plugins = self._registry.list_plugins_by_type(PluginType.ENRICHER)
        return [p for p in plugins if isinstance(p, EnricherPlugin)]

    def get_alert_destinations(self) -> list[AlertDestinationPlugin]:
        """Get all loaded alert destination plugins."""
        plugins = self._registry.list_plugins_by_type(PluginType.ALERT_DESTINATION)
        return [p for p in plugins if isinstance(p, AlertDestinationPlugin)]

    def get_report_formats(self) -> list[ReportFormatPlugin]:
        """Get all loaded report format plugins."""
        plugins = self._registry.list_plugins_by_type(PluginType.REPORT_FORMAT)
        return [p for p in plugins if isinstance(p, ReportFormatPlugin)]

    def get_collector(self, name: str) -> CollectorPlugin | None:
        """Get a specific collector plugin."""
        return self._registry.get_plugin_typed(name, CollectorPlugin)

    def get_policy(self, name: str) -> PolicyPlugin | None:
        """Get a specific policy plugin."""
        return self._registry.get_plugin_typed(name, PolicyPlugin)

    def get_enricher(self, name: str) -> EnricherPlugin | None:
        """Get a specific enricher plugin."""
        return self._registry.get_plugin_typed(name, EnricherPlugin)

    def get_alert_destination(self, name: str) -> AlertDestinationPlugin | None:
        """Get a specific alert destination plugin."""
        return self._registry.get_plugin_typed(name, AlertDestinationPlugin)

    def get_report_format(self, name: str) -> ReportFormatPlugin | None:
        """Get a specific report format plugin."""
        return self._registry.get_plugin_typed(name, ReportFormatPlugin)

    def enable_plugin(self, plugin_name: str) -> bool:
        """Enable a plugin."""
        return self._registry.enable_plugin(plugin_name)

    def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a plugin."""
        return self._registry.disable_plugin(plugin_name)

    def shutdown(self) -> None:
        """Shutdown all plugins and clear registry."""
        with self._lock:
            self._registry.clear()
            self._initialized = False

    @property
    def plugin_count(self) -> int:
        """Get total number of registered plugins."""
        return self._registry.plugin_count

    @property
    def loaded_count(self) -> int:
        """Get number of loaded plugins."""
        return self._registry.loaded_count


# Global manager instance
_global_manager: PluginManager | None = None
_manager_lock = threading.Lock()


def get_plugin_manager(
    config_path: str | Path | None = None,
    auto_discover: bool = True,
) -> PluginManager:
    """
    Get the global plugin manager.

    Args:
        config_path: Plugin configuration path
        auto_discover: Auto-discover plugins on first call

    Returns:
        Global PluginManager instance
    """
    global _global_manager
    with _manager_lock:
        if _global_manager is None:
            _global_manager = PluginManager(
                config_path=config_path,
                auto_discover=auto_discover,
            )
        return _global_manager
