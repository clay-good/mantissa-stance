# stance.plugins.loader

Plugin loader for Mantissa Stance.

Handles plugin discovery and dynamic loading from various sources.

## Contents

### Classes

- [PluginLoader](#pluginloader)

### Functions

- [discover_plugins](#discover_plugins)
- [load_plugin](#load_plugin)

## PluginLoader

Loads plugins from various sources.

Supports loading from:
- Python modules
- Directory paths
- Entry points

### Methods

#### `__init__(self, registry: PluginRegistry | None, plugin_dirs: list[str] | None)`

Initialize the plugin loader.

**Parameters:**

- `registry` (`PluginRegistry | None`) - Plugin registry to use (default: global registry)
- `plugin_dirs` (`list[str] | None`) - Additional directories to search for plugins

#### `discover_plugins(self) -> list[str]`

Discover available plugins in plugin directories.

**Returns:**

`list[str]` - List of discovered plugin module paths

#### `load_plugin_from_file(self, file_path: str, config: dict[(str, Any)] | None) -> PluginInfo`

Load a plugin from a Python file.

**Parameters:**

- `file_path` (`str`) - Path to the plugin file
- `config` (`dict[(str, Any)] | None`) - Optional plugin configuration

**Returns:**

`PluginInfo` - PluginInfo for the loaded plugin

**Raises:**

- `PluginLoadError`: If plugin cannot be loaded

#### `load_plugin_from_module(self, module_name: str, config: dict[(str, Any)] | None) -> PluginInfo`

Load a plugin from an installed Python module.

**Parameters:**

- `module_name` (`str`) - Fully qualified module name
- `config` (`dict[(str, Any)] | None`) - Optional plugin configuration

**Returns:**

`PluginInfo` - PluginInfo for the loaded plugin

**Raises:**

- `PluginLoadError`: If plugin cannot be loaded

#### `load_plugin_class(self, plugin_class: type[Plugin], config: dict[(str, Any)] | None) -> PluginInfo`

Load a plugin from a class directly.

**Parameters:**

- `plugin_class` (`type[Plugin]`) - Plugin class to load
- `config` (`dict[(str, Any)] | None`) - Optional plugin configuration

**Returns:**

`PluginInfo` - PluginInfo for the loaded plugin

**Raises:**

- `PluginLoadError`: If plugin cannot be loaded

#### `load_all_discovered(self, configs: dict[(str, dict[(str, Any)])] | None) -> list[PluginInfo]`

Load all discovered plugins.

**Parameters:**

- `configs` (`dict[(str, dict[(str, Any)])] | None`) - Dict mapping plugin names to configurations

**Returns:**

`list[PluginInfo]` - List of PluginInfo for loaded plugins

#### `load_from_entry_points(self, group: str = stance.plugins) -> list[PluginInfo]`

Load plugins from package entry points.

**Parameters:**

- `group` (`str`) - default: `stance.plugins` - Entry point group name

**Returns:**

`list[PluginInfo]` - List of PluginInfo for loaded plugins

### `discover_plugins(plugin_dirs: list[str] | None) -> list[str]`

Discover available plugins.

**Parameters:**

- `plugin_dirs` (`list[str] | None`) - Additional directories to search

**Returns:**

`list[str]` - List of discovered plugin paths

### `load_plugin(source: str | type[Plugin], config: dict[(str, Any)] | None, registry: PluginRegistry | None) -> PluginInfo`

Load a plugin from various sources.

**Parameters:**

- `source` (`str | type[Plugin]`) - File path, module name, or Plugin class
- `config` (`dict[(str, Any)] | None`) - Optional plugin configuration
- `registry` (`PluginRegistry | None`) - Plugin registry to use

**Returns:**

`PluginInfo` - PluginInfo for the loaded plugin

**Raises:**

- `PluginLoadError`: If plugin cannot be loaded
