# stance.plugins.manager

Plugin manager for Mantissa Stance.

Provides high-level plugin lifecycle management and coordination.

## Contents

### Classes

- [PluginManager](#pluginmanager)

### Functions

- [get_plugin_manager](#get_plugin_manager)

## Constants

### `T`

Type: `str`

Value: `TypeVar(...)`

## PluginManager

High-level manager for plugin lifecycle.

Coordinates plugin loading, configuration, and access
with support for persistence and hot-reloading.

### Properties

#### `plugin_count(self) -> int`

Get total number of registered plugins.

**Returns:**

`int`

#### `loaded_count(self) -> int`

Get number of loaded plugins.

**Returns:**

`int`

### Methods

#### `__init__(self, registry: PluginRegistry | None, config_path: str | Path | None, auto_discover: bool = True)`

Initialize the plugin manager.

**Parameters:**

- `registry` (`PluginRegistry | None`) - Plugin registry to use
- `config_path` (`str | Path | None`) - Path to plugin configuration file
- `auto_discover` (`bool`) - default: `True` - Automatically discover plugins on init

#### `discover_and_load(self) -> list[PluginInfo]`

Discover and load all available plugins.

**Returns:**

`list[PluginInfo]` - List of PluginInfo for loaded plugins

#### `load_plugin(self, source: str | type[Plugin], config: dict[(str, Any)] | None) -> PluginInfo`

Load a plugin from a source.

**Parameters:**

- `source` (`str | type[Plugin]`) - File path, module name, or Plugin class
- `config` (`dict[(str, Any)] | None`) - Plugin configuration

**Returns:**

`PluginInfo` - PluginInfo for the loaded plugin

#### `unload_plugin(self, plugin_name: str) -> bool`

Unload a plugin.

**Parameters:**

- `plugin_name` (`str`) - Name of plugin to unload

**Returns:**

`bool` - True if plugin was unloaded

#### `reload_plugin(self, plugin_name: str) -> PluginInfo | None`

Reload a plugin.

**Parameters:**

- `plugin_name` (`str`) - Name of plugin to reload

**Returns:**

`PluginInfo | None` - New PluginInfo or None if reload failed

#### `configure_plugin(self, plugin_name: str, config: dict[(str, Any)]) -> bool`

Configure a plugin.

**Parameters:**

- `plugin_name` (`str`) - Name of plugin to configure
- `config` (`dict[(str, Any)]`) - New configuration

**Returns:**

`bool` - True if configuration was applied

#### `get_plugin(self, plugin_name: str) -> Plugin | None`

Get a plugin instance.

**Parameters:**

- `plugin_name` (`str`) - Name of the plugin

**Returns:**

`Plugin | None` - Plugin instance or None

#### `get_plugin_info(self, plugin_name: str) -> PluginInfo | None`

Get plugin information.

**Parameters:**

- `plugin_name` (`str`) - Name of the plugin

**Returns:**

`PluginInfo | None` - PluginInfo or None

#### `list_plugins(self, plugin_type: PluginType | None, enabled_only: bool = False) -> list[PluginInfo]`

List registered plugins.

**Parameters:**

- `plugin_type` (`PluginType | None`) - Filter by type
- `enabled_only` (`bool`) - default: `False` - Only enabled plugins

**Returns:**

`list[PluginInfo]` - List of PluginInfo

#### `get_collectors(self) -> list[CollectorPlugin]`

Get all loaded collector plugins.

**Returns:**

`list[CollectorPlugin]`

#### `get_policies(self) -> list[PolicyPlugin]`

Get all loaded policy plugins.

**Returns:**

`list[PolicyPlugin]`

#### `get_enrichers(self) -> list[EnricherPlugin]`

Get all loaded enricher plugins.

**Returns:**

`list[EnricherPlugin]`

#### `get_alert_destinations(self) -> list[AlertDestinationPlugin]`

Get all loaded alert destination plugins.

**Returns:**

`list[AlertDestinationPlugin]`

#### `get_report_formats(self) -> list[ReportFormatPlugin]`

Get all loaded report format plugins.

**Returns:**

`list[ReportFormatPlugin]`

#### `get_collector(self, name: str) -> CollectorPlugin | None`

Get a specific collector plugin.

**Parameters:**

- `name` (`str`)

**Returns:**

`CollectorPlugin | None`

#### `get_policy(self, name: str) -> PolicyPlugin | None`

Get a specific policy plugin.

**Parameters:**

- `name` (`str`)

**Returns:**

`PolicyPlugin | None`

#### `get_enricher(self, name: str) -> EnricherPlugin | None`

Get a specific enricher plugin.

**Parameters:**

- `name` (`str`)

**Returns:**

`EnricherPlugin | None`

#### `get_alert_destination(self, name: str) -> AlertDestinationPlugin | None`

Get a specific alert destination plugin.

**Parameters:**

- `name` (`str`)

**Returns:**

`AlertDestinationPlugin | None`

#### `get_report_format(self, name: str) -> ReportFormatPlugin | None`

Get a specific report format plugin.

**Parameters:**

- `name` (`str`)

**Returns:**

`ReportFormatPlugin | None`

#### `enable_plugin(self, plugin_name: str) -> bool`

Enable a plugin.

**Parameters:**

- `plugin_name` (`str`)

**Returns:**

`bool`

#### `disable_plugin(self, plugin_name: str) -> bool`

Disable a plugin.

**Parameters:**

- `plugin_name` (`str`)

**Returns:**

`bool`

#### `shutdown(self) -> None`

Shutdown all plugins and clear registry.

**Returns:**

`None`

### `get_plugin_manager(config_path: str | Path | None, auto_discover: bool = True) -> PluginManager`

Get the global plugin manager.

**Parameters:**

- `config_path` (`str | Path | None`) - Plugin configuration path
- `auto_discover` (`bool`) - default: `True` - Auto-discover plugins on first call

**Returns:**

`PluginManager` - Global PluginManager instance
