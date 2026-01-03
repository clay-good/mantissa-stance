"""
Plugin loader for Mantissa Stance.

Handles plugin discovery and dynamic loading from various sources.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys
from pathlib import Path
from typing import Any

from stance.plugins.base import (
    Plugin,
    PluginType,
    PluginInfo,
    PluginLoadError,
    PluginMetadata,
)
from stance.plugins.registry import PluginRegistry, get_registry


class PluginLoader:
    """
    Loads plugins from various sources.

    Supports loading from:
    - Python modules
    - Directory paths
    - Entry points
    """

    def __init__(
        self,
        registry: PluginRegistry | None = None,
        plugin_dirs: list[str] | None = None,
    ):
        """
        Initialize the plugin loader.

        Args:
            registry: Plugin registry to use (default: global registry)
            plugin_dirs: Additional directories to search for plugins
        """
        self._registry = registry or get_registry()
        self._plugin_dirs = plugin_dirs or []
        self._default_plugin_dir = self._get_default_plugin_dir()

    def _get_default_plugin_dir(self) -> Path:
        """Get the default plugin directory."""
        # Check environment variable first
        env_dir = os.environ.get("STANCE_PLUGIN_DIR")
        if env_dir:
            return Path(env_dir)

        # Default to ~/.stance/plugins
        home = Path.home()
        return home / ".stance" / "plugins"

    def discover_plugins(self) -> list[str]:
        """
        Discover available plugins in plugin directories.

        Returns:
            List of discovered plugin module paths
        """
        discovered = []

        # Search default directory
        if self._default_plugin_dir.exists():
            discovered.extend(self._discover_in_directory(self._default_plugin_dir))

        # Search additional directories
        for dir_path in self._plugin_dirs:
            path = Path(dir_path)
            if path.exists():
                discovered.extend(self._discover_in_directory(path))

        return discovered

    def _discover_in_directory(self, directory: Path) -> list[str]:
        """
        Discover plugins in a directory.

        Args:
            directory: Directory to search

        Returns:
            List of plugin file paths
        """
        discovered = []

        # Look for Python files with plugin marker
        for item in directory.iterdir():
            if item.is_file() and item.suffix == ".py":
                if not item.name.startswith("_"):
                    discovered.append(str(item))
            elif item.is_dir() and not item.name.startswith("_"):
                # Check for plugin package (has __init__.py)
                init_file = item / "__init__.py"
                if init_file.exists():
                    discovered.append(str(item))

        return discovered

    def load_plugin_from_file(
        self,
        file_path: str,
        config: dict[str, Any] | None = None,
    ) -> PluginInfo:
        """
        Load a plugin from a Python file.

        Args:
            file_path: Path to the plugin file
            config: Optional plugin configuration

        Returns:
            PluginInfo for the loaded plugin

        Raises:
            PluginLoadError: If plugin cannot be loaded
        """
        path = Path(file_path)
        if not path.exists():
            raise PluginLoadError(f"Plugin file not found: {file_path}")

        try:
            # Generate unique module name
            module_name = f"stance_plugin_{path.stem}"

            # Load the module
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                raise PluginLoadError(f"Cannot load module spec from: {file_path}")

            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            # Find plugin class in module
            plugin_class = self._find_plugin_class(module)
            if plugin_class is None:
                raise PluginLoadError(f"No Plugin subclass found in: {file_path}")

            # Register the plugin
            return self._registry.register(
                plugin_class,
                module_path=file_path,
                config=config,
            )

        except PluginLoadError:
            raise
        except Exception as e:
            raise PluginLoadError(f"Failed to load plugin from {file_path}: {e}")

    def load_plugin_from_module(
        self,
        module_name: str,
        config: dict[str, Any] | None = None,
    ) -> PluginInfo:
        """
        Load a plugin from an installed Python module.

        Args:
            module_name: Fully qualified module name
            config: Optional plugin configuration

        Returns:
            PluginInfo for the loaded plugin

        Raises:
            PluginLoadError: If plugin cannot be loaded
        """
        try:
            module = importlib.import_module(module_name)

            # Find plugin class in module
            plugin_class = self._find_plugin_class(module)
            if plugin_class is None:
                raise PluginLoadError(f"No Plugin subclass found in: {module_name}")

            # Register the plugin
            return self._registry.register(
                plugin_class,
                module_path=module_name,
                config=config,
            )

        except ImportError as e:
            raise PluginLoadError(f"Cannot import module {module_name}: {e}")
        except PluginLoadError:
            raise
        except Exception as e:
            raise PluginLoadError(f"Failed to load plugin from {module_name}: {e}")

    def load_plugin_class(
        self,
        plugin_class: type[Plugin],
        config: dict[str, Any] | None = None,
    ) -> PluginInfo:
        """
        Load a plugin from a class directly.

        Args:
            plugin_class: Plugin class to load
            config: Optional plugin configuration

        Returns:
            PluginInfo for the loaded plugin

        Raises:
            PluginLoadError: If plugin cannot be loaded
        """
        try:
            module_path = f"{plugin_class.__module__}.{plugin_class.__name__}"
            return self._registry.register(
                plugin_class,
                module_path=module_path,
                config=config,
            )
        except Exception as e:
            raise PluginLoadError(f"Failed to load plugin class: {e}")

    def _find_plugin_class(self, module: Any) -> type[Plugin] | None:
        """
        Find a Plugin subclass in a module.

        Args:
            module: Module to search

        Returns:
            Plugin class or None if not found
        """
        for name in dir(module):
            obj = getattr(module, name)
            if (
                isinstance(obj, type)
                and issubclass(obj, Plugin)
                and obj is not Plugin
                and not name.startswith("_")
            ):
                # Check it's not an imported base class
                if obj.__module__ == module.__name__:
                    return obj

        return None

    def load_all_discovered(
        self,
        configs: dict[str, dict[str, Any]] | None = None,
    ) -> list[PluginInfo]:
        """
        Load all discovered plugins.

        Args:
            configs: Dict mapping plugin names to configurations

        Returns:
            List of PluginInfo for loaded plugins
        """
        configs = configs or {}
        results = []

        for path in self.discover_plugins():
            try:
                # Try to peek at plugin name for config lookup
                info = self.load_plugin_from_file(
                    path,
                    config=configs.get(Path(path).stem, {}),
                )
                results.append(info)
            except PluginLoadError:
                # Skip plugins that fail to load
                pass

        return results

    def load_from_entry_points(
        self,
        group: str = "stance.plugins",
    ) -> list[PluginInfo]:
        """
        Load plugins from package entry points.

        Args:
            group: Entry point group name

        Returns:
            List of PluginInfo for loaded plugins
        """
        results = []

        try:
            # Python 3.10+ has importlib.metadata
            from importlib.metadata import entry_points

            eps = entry_points()
            if hasattr(eps, "select"):
                # Python 3.10+
                plugin_eps = eps.select(group=group)
            else:
                # Python 3.9
                plugin_eps = eps.get(group, [])

            for ep in plugin_eps:
                try:
                    plugin_class = ep.load()
                    if issubclass(plugin_class, Plugin):
                        info = self._registry.register(
                            plugin_class,
                            module_path=f"{ep.value} (entry point)",
                        )
                        results.append(info)
                except Exception:
                    # Skip entry points that fail to load
                    pass

        except ImportError:
            # importlib.metadata not available
            pass

        return results


def discover_plugins(plugin_dirs: list[str] | None = None) -> list[str]:
    """
    Discover available plugins.

    Args:
        plugin_dirs: Additional directories to search

    Returns:
        List of discovered plugin paths
    """
    loader = PluginLoader(plugin_dirs=plugin_dirs)
    return loader.discover_plugins()


def load_plugin(
    source: str | type[Plugin],
    config: dict[str, Any] | None = None,
    registry: PluginRegistry | None = None,
) -> PluginInfo:
    """
    Load a plugin from various sources.

    Args:
        source: File path, module name, or Plugin class
        config: Optional plugin configuration
        registry: Plugin registry to use

    Returns:
        PluginInfo for the loaded plugin

    Raises:
        PluginLoadError: If plugin cannot be loaded
    """
    loader = PluginLoader(registry=registry)

    if isinstance(source, type) and issubclass(source, Plugin):
        return loader.load_plugin_class(source, config)

    if isinstance(source, str):
        path = Path(source)
        if path.exists():
            return loader.load_plugin_from_file(source, config)
        else:
            return loader.load_plugin_from_module(source, config)

    raise PluginLoadError(f"Invalid plugin source: {source}")
