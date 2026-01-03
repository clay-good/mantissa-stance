# stance.plugins.registry

Plugin registry for Mantissa Stance.

Provides a central registry for discovering, registering, and
accessing plugins.

## Contents

### Classes

- [PluginRegistry](#pluginregistry)

### Functions

- [get_registry](#get_registry)

## Constants

### `T`

Type: `str`

Value: `TypeVar(...)`

## PluginRegistry

Central registry for all plugins.

Thread-safe registry that stores plugin information
and provides access to loaded plugin instances.

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

#### `__init__(self)`

Initialize the registry.

#### `register(self, plugin_class: type[Plugin], module_path: str = , config: dict[(str, Any)] | None) -> PluginInfo`

Register a plugin class.

**Parameters:**

- `plugin_class` (`type[Plugin]`) - Plugin class to register
- `module_path` (`str`) - default: `` - Path to the module containing the plugin
- `config` (`dict[(str, Any)] | None`) - Optional configuration for the plugin

**Returns:**

`PluginInfo` - PluginInfo for the registered plugin

**Raises:**

- `PluginError`: If plugin is already registered

#### `unregister(self, plugin_name: str) -> bool`

Unregister a plugin.

**Parameters:**

- `plugin_name` (`str`) - Name of plugin to unregister

**Returns:**

`bool` - True if plugin was unregistered, False if not found

#### `get_plugin_info(self, plugin_name: str) -> PluginInfo | None`

Get information about a plugin.

**Parameters:**

- `plugin_name` (`str`) - Name of the plugin

**Returns:**

`PluginInfo | None` - PluginInfo or None if not found

#### `get_plugin(self, plugin_name: str) -> Plugin | None`

Get a plugin instance.

**Parameters:**

- `plugin_name` (`str`) - Name of the plugin

**Returns:**

`Plugin | None` - Plugin instance or None if not found/loaded

#### `get_plugin_typed(self, plugin_name: str, plugin_type: type[T]) -> T | None`

Get a plugin instance with type checking.

**Parameters:**

- `plugin_name` (`str`) - Name of the plugin
- `plugin_type` (`type[T]`) - Expected plugin type class

**Returns:**

`T | None` - Plugin instance of the specified type, or None

#### `list_plugins(self, plugin_type: PluginType | None, enabled_only: bool = False, loaded_only: bool = False) -> list[PluginInfo]`

List registered plugins.

**Parameters:**

- `plugin_type` (`PluginType | None`) - Filter by plugin type
- `enabled_only` (`bool`) - default: `False` - Only return enabled plugins
- `loaded_only` (`bool`) - default: `False` - Only return loaded plugins

**Returns:**

`list[PluginInfo]` - List of PluginInfo objects

#### `list_plugins_by_type(self, plugin_type: PluginType) -> list[Plugin]`

List plugin instances by type.

**Parameters:**

- `plugin_type` (`PluginType`) - Type of plugins to list

**Returns:**

`list[Plugin]` - List of plugin instances

#### `enable_plugin(self, plugin_name: str) -> bool`

Enable a plugin.

**Parameters:**

- `plugin_name` (`str`) - Name of plugin to enable

**Returns:**

`bool` - True if plugin was enabled

#### `disable_plugin(self, plugin_name: str) -> bool`

Disable a plugin.

**Parameters:**

- `plugin_name` (`str`) - Name of plugin to disable

**Returns:**

`bool` - True if plugin was disabled

#### `configure_plugin(self, plugin_name: str, config: dict[(str, Any)]) -> bool`

Configure a plugin.

**Parameters:**

- `plugin_name` (`str`) - Name of plugin to configure
- `config` (`dict[(str, Any)]`) - New configuration

**Returns:**

`bool` - True if plugin was configured successfully

#### `clear(self) -> None`

Clear all registered plugins.

**Returns:**

`None`

### `get_registry() -> PluginRegistry`

Get the global plugin registry.

**Returns:**

`PluginRegistry` - Global PluginRegistry instance
