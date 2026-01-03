"""
Plugin registry for Mantissa Stance.

Provides a central registry for discovering, registering, and
accessing plugins.
"""

from __future__ import annotations

import threading
from typing import Any, TypeVar

from stance.plugins.base import (
    Plugin,
    PluginType,
    PluginInfo,
    PluginError,
)

T = TypeVar("T", bound=Plugin)


class PluginRegistry:
    """
    Central registry for all plugins.

    Thread-safe registry that stores plugin information
    and provides access to loaded plugin instances.
    """

    def __init__(self):
        """Initialize the registry."""
        self._plugins: dict[str, PluginInfo] = {}
        self._instances: dict[str, Plugin] = {}
        self._lock = threading.RLock()

    def register(
        self,
        plugin_class: type[Plugin],
        module_path: str = "",
        config: dict[str, Any] | None = None,
    ) -> PluginInfo:
        """
        Register a plugin class.

        Args:
            plugin_class: Plugin class to register
            module_path: Path to the module containing the plugin
            config: Optional configuration for the plugin

        Returns:
            PluginInfo for the registered plugin

        Raises:
            PluginError: If plugin is already registered
        """
        with self._lock:
            metadata = plugin_class.get_metadata()
            plugin_name = metadata.name

            if plugin_name in self._plugins:
                raise PluginError(f"Plugin '{plugin_name}' is already registered")

            info = PluginInfo(
                metadata=metadata,
                module_path=module_path,
                is_enabled=True,
                is_loaded=False,
                config=config or {},
            )

            self._plugins[plugin_name] = info

            # Try to instantiate the plugin
            try:
                instance = plugin_class()
                instance.initialize(info.config)
                self._instances[plugin_name] = instance
                info.is_loaded = True
            except Exception as e:
                info.load_error = str(e)
                info.is_loaded = False

            return info

    def unregister(self, plugin_name: str) -> bool:
        """
        Unregister a plugin.

        Args:
            plugin_name: Name of plugin to unregister

        Returns:
            True if plugin was unregistered, False if not found
        """
        with self._lock:
            if plugin_name not in self._plugins:
                return False

            # Shutdown instance if loaded
            if plugin_name in self._instances:
                try:
                    self._instances[plugin_name].shutdown()
                except Exception:
                    pass
                del self._instances[plugin_name]

            del self._plugins[plugin_name]
            return True

    def get_plugin_info(self, plugin_name: str) -> PluginInfo | None:
        """
        Get information about a plugin.

        Args:
            plugin_name: Name of the plugin

        Returns:
            PluginInfo or None if not found
        """
        with self._lock:
            return self._plugins.get(plugin_name)

    def get_plugin(self, plugin_name: str) -> Plugin | None:
        """
        Get a plugin instance.

        Args:
            plugin_name: Name of the plugin

        Returns:
            Plugin instance or None if not found/loaded
        """
        with self._lock:
            return self._instances.get(plugin_name)

    def get_plugin_typed(self, plugin_name: str, plugin_type: type[T]) -> T | None:
        """
        Get a plugin instance with type checking.

        Args:
            plugin_name: Name of the plugin
            plugin_type: Expected plugin type class

        Returns:
            Plugin instance of the specified type, or None
        """
        plugin = self.get_plugin(plugin_name)
        if plugin is not None and isinstance(plugin, plugin_type):
            return plugin
        return None

    def list_plugins(
        self,
        plugin_type: PluginType | None = None,
        enabled_only: bool = False,
        loaded_only: bool = False,
    ) -> list[PluginInfo]:
        """
        List registered plugins.

        Args:
            plugin_type: Filter by plugin type
            enabled_only: Only return enabled plugins
            loaded_only: Only return loaded plugins

        Returns:
            List of PluginInfo objects
        """
        with self._lock:
            plugins = list(self._plugins.values())

            if plugin_type is not None:
                plugins = [p for p in plugins if p.plugin_type == plugin_type]

            if enabled_only:
                plugins = [p for p in plugins if p.is_enabled]

            if loaded_only:
                plugins = [p for p in plugins if p.is_loaded]

            return plugins

    def list_plugins_by_type(self, plugin_type: PluginType) -> list[Plugin]:
        """
        List plugin instances by type.

        Args:
            plugin_type: Type of plugins to list

        Returns:
            List of plugin instances
        """
        with self._lock:
            result = []
            for info in self._plugins.values():
                if info.plugin_type == plugin_type and info.is_loaded:
                    instance = self._instances.get(info.name)
                    if instance:
                        result.append(instance)
            return result

    def enable_plugin(self, plugin_name: str) -> bool:
        """
        Enable a plugin.

        Args:
            plugin_name: Name of plugin to enable

        Returns:
            True if plugin was enabled
        """
        with self._lock:
            info = self._plugins.get(plugin_name)
            if info:
                info.is_enabled = True
                return True
            return False

    def disable_plugin(self, plugin_name: str) -> bool:
        """
        Disable a plugin.

        Args:
            plugin_name: Name of plugin to disable

        Returns:
            True if plugin was disabled
        """
        with self._lock:
            info = self._plugins.get(plugin_name)
            if info:
                info.is_enabled = False
                return True
            return False

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
            True if plugin was configured successfully
        """
        with self._lock:
            info = self._plugins.get(plugin_name)
            if not info:
                return False

            # Validate config if plugin is loaded
            instance = self._instances.get(plugin_name)
            if instance:
                errors = instance.validate_config(config)
                if errors:
                    return False

                # Re-initialize with new config
                try:
                    instance.shutdown()
                    instance.initialize(config)
                except Exception:
                    return False

            info.config = config
            return True

    def clear(self) -> None:
        """Clear all registered plugins."""
        with self._lock:
            # Shutdown all instances
            for instance in self._instances.values():
                try:
                    instance.shutdown()
                except Exception:
                    pass

            self._plugins.clear()
            self._instances.clear()

    @property
    def plugin_count(self) -> int:
        """Get total number of registered plugins."""
        with self._lock:
            return len(self._plugins)

    @property
    def loaded_count(self) -> int:
        """Get number of loaded plugins."""
        with self._lock:
            return len(self._instances)


# Global registry instance
_global_registry: PluginRegistry | None = None
_registry_lock = threading.Lock()


def get_registry() -> PluginRegistry:
    """
    Get the global plugin registry.

    Returns:
        Global PluginRegistry instance
    """
    global _global_registry
    with _registry_lock:
        if _global_registry is None:
            _global_registry = PluginRegistry()
        return _global_registry
