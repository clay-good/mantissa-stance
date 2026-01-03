# stance.plugins.base

Base plugin types and errors for Mantissa Stance.

Defines the core abstractions for the plugin system.

## Contents

### Classes

- [PluginType](#plugintype)
- [PluginError](#pluginerror)
- [PluginLoadError](#pluginloaderror)
- [PluginConfigError](#pluginconfigerror)
- [PluginNotFoundError](#pluginnotfounderror)
- [PluginMetadata](#pluginmetadata)
- [PluginInfo](#plugininfo)
- [Plugin](#plugin)

## PluginType

**Inherits from:** Enum

Types of plugins supported.

## PluginError

**Inherits from:** Exception

Base exception for plugin errors.

## PluginLoadError

**Inherits from:** PluginError

Error loading a plugin.

## PluginConfigError

**Inherits from:** PluginError

Error in plugin configuration.

## PluginNotFoundError

**Inherits from:** PluginError

Error when a plugin is not found.

## PluginMetadata

**Tags:** dataclass

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

### Attributes

| Name | Type | Default |
|------|------|---------|
| `name` | `str` | - |
| `version` | `str` | - |
| `description` | `str` | - |
| `author` | `str` | `` |
| `plugin_type` | `PluginType` | `"Attribute(value=Name(id='PluginType', ctx=Load()), attr='COLLECTOR', ctx=Load())"` |
| `tags` | `list[str]` | `field(...)` |
| `dependencies` | `list[str]` | `field(...)` |
| `config_schema` | `dict[(str, Any)] | None` | - |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## PluginInfo

**Tags:** dataclass

Runtime information about a loaded plugin.

Attributes:
    metadata: Plugin metadata
    module_path: Path to the plugin module
    is_enabled: Whether plugin is enabled
    is_loaded: Whether plugin class is loaded
    load_error: Error message if loading failed
    config: Plugin configuration

### Attributes

| Name | Type | Default |
|------|------|---------|
| `metadata` | `PluginMetadata` | - |
| `module_path` | `str` | `` |
| `is_enabled` | `bool` | `True` |
| `is_loaded` | `bool` | `False` |
| `load_error` | `str | None` | - |
| `config` | `dict[(str, Any)]` | `field(...)` |

### Properties

#### `name(self) -> str`

Get plugin name.

**Returns:**

`str`

#### `version(self) -> str`

Get plugin version.

**Returns:**

`str`

#### `plugin_type(self) -> PluginType`

Get plugin type.

**Returns:**

`PluginType`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## Plugin

**Inherits from:** ABC

Base class for all Stance plugins.

All plugins must inherit from this class and implement
the required abstract methods.

### Properties

#### `name(self) -> str`

Get plugin name.

**Returns:**

`str`

#### `version(self) -> str`

Get plugin version.

**Returns:**

`str`

#### `plugin_type(self) -> PluginType`

Get plugin type.

**Returns:**

`PluginType`

### Methods

#### `initialize(self, config: dict[(str, Any)]) -> None`

**Decorators:** @abstractmethod

Initialize the plugin with configuration.

**Parameters:**

- `config` (`dict[(str, Any)]`) - Plugin configuration dictionary

**Returns:**

`None`

**Raises:**

- `PluginConfigError`: If configuration is invalid

#### `shutdown(self) -> None`

**Decorators:** @abstractmethod

Shutdown the plugin and release resources.  Called when the plugin is being unloaded.

**Returns:**

`None`

#### `validate_config(self, config: dict[(str, Any)]) -> list[str]`

Validate plugin configuration.

**Parameters:**

- `config` (`dict[(str, Any)]`) - Configuration to validate

**Returns:**

`list[str]` - List of validation error messages (empty if valid)

### Class Methods

#### `get_metadata(cls) -> PluginMetadata`

**Decorators:** @classmethod, @abstractmethod

Get plugin metadata.

**Returns:**

`PluginMetadata` - PluginMetadata describing the plugin
