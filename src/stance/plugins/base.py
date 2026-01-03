"""
Base plugin types and errors for Mantissa Stance.

Defines the core abstractions for the plugin system.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PluginType(Enum):
    """Types of plugins supported."""

    COLLECTOR = "collector"
    POLICY = "policy"
    ENRICHER = "enricher"
    ALERT_DESTINATION = "alert_destination"
    REPORT_FORMAT = "report_format"


class PluginError(Exception):
    """Base exception for plugin errors."""

    pass


class PluginLoadError(PluginError):
    """Error loading a plugin."""

    pass


class PluginConfigError(PluginError):
    """Error in plugin configuration."""

    pass


class PluginNotFoundError(PluginError):
    """Error when a plugin is not found."""

    pass


@dataclass
class PluginMetadata:
    """
    Metadata describing a plugin.

    Attributes:
        name: Unique plugin name
        version: Plugin version string
        description: Human-readable description
        author: Plugin author
        plugin_type: Type of plugin
        tags: Optional tags for categorization
        dependencies: Required dependencies
        config_schema: JSON schema for configuration (if any)
    """

    name: str
    version: str
    description: str
    author: str = ""
    plugin_type: PluginType = PluginType.COLLECTOR
    tags: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    config_schema: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "plugin_type": self.plugin_type.value,
            "tags": self.tags,
            "dependencies": self.dependencies,
            "config_schema": self.config_schema,
        }


@dataclass
class PluginInfo:
    """
    Runtime information about a loaded plugin.

    Attributes:
        metadata: Plugin metadata
        module_path: Path to the plugin module
        is_enabled: Whether plugin is enabled
        is_loaded: Whether plugin class is loaded
        load_error: Error message if loading failed
        config: Plugin configuration
    """

    metadata: PluginMetadata
    module_path: str = ""
    is_enabled: bool = True
    is_loaded: bool = False
    load_error: str | None = None
    config: dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        """Get plugin name."""
        return self.metadata.name

    @property
    def version(self) -> str:
        """Get plugin version."""
        return self.metadata.version

    @property
    def plugin_type(self) -> PluginType:
        """Get plugin type."""
        return self.metadata.plugin_type

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "metadata": self.metadata.to_dict(),
            "module_path": self.module_path,
            "is_enabled": self.is_enabled,
            "is_loaded": self.is_loaded,
            "load_error": self.load_error,
        }


class Plugin(ABC):
    """
    Base class for all Stance plugins.

    All plugins must inherit from this class and implement
    the required abstract methods.
    """

    @classmethod
    @abstractmethod
    def get_metadata(cls) -> PluginMetadata:
        """
        Get plugin metadata.

        Returns:
            PluginMetadata describing the plugin
        """
        pass

    @abstractmethod
    def initialize(self, config: dict[str, Any]) -> None:
        """
        Initialize the plugin with configuration.

        Args:
            config: Plugin configuration dictionary

        Raises:
            PluginConfigError: If configuration is invalid
        """
        pass

    @abstractmethod
    def shutdown(self) -> None:
        """
        Shutdown the plugin and release resources.

        Called when the plugin is being unloaded.
        """
        pass

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        """
        Validate plugin configuration.

        Args:
            config: Configuration to validate

        Returns:
            List of validation error messages (empty if valid)
        """
        return []

    @property
    def name(self) -> str:
        """Get plugin name."""
        return self.get_metadata().name

    @property
    def version(self) -> str:
        """Get plugin version."""
        return self.get_metadata().version

    @property
    def plugin_type(self) -> PluginType:
        """Get plugin type."""
        return self.get_metadata().plugin_type
