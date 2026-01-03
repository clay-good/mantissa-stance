"""
Mantissa Stance Plugin System.

Provides extensibility through a plugin architecture supporting:
- Custom collectors
- Custom policies
- Custom enrichers
- Custom alert destinations
- Custom report formats
"""

from __future__ import annotations

from stance.plugins.base import (
    Plugin,
    PluginType,
    PluginMetadata,
    PluginInfo,
    PluginError,
    PluginLoadError,
    PluginConfigError,
    PluginNotFoundError,
)
from stance.plugins.interfaces import (
    CollectorPlugin,
    PolicyPlugin,
    EnricherPlugin,
    AlertDestinationPlugin,
    ReportFormatPlugin,
)
from stance.plugins.registry import (
    PluginRegistry,
    get_registry,
)
from stance.plugins.loader import (
    PluginLoader,
    discover_plugins,
    load_plugin,
)
from stance.plugins.manager import (
    PluginManager,
    get_plugin_manager,
)

__all__ = [
    # Base types
    "Plugin",
    "PluginType",
    "PluginMetadata",
    "PluginInfo",
    "PluginError",
    "PluginLoadError",
    "PluginConfigError",
    "PluginNotFoundError",
    # Interfaces
    "CollectorPlugin",
    "PolicyPlugin",
    "EnricherPlugin",
    "AlertDestinationPlugin",
    "ReportFormatPlugin",
    # Registry
    "PluginRegistry",
    "get_registry",
    # Loader
    "PluginLoader",
    "discover_plugins",
    "load_plugin",
    # Manager
    "PluginManager",
    "get_plugin_manager",
]
