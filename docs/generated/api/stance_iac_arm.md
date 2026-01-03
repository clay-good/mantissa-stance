# stance.iac.arm

Azure Resource Manager (ARM) template parser for Mantissa Stance.

Provides parsing of Azure ARM templates in JSON format.
ARM templates define Azure resources using a declarative JSON syntax.

Supported constructs:
- Resources (with nested resources)
- Parameters
- Variables
- Outputs
- Functions (parsed but not evaluated)
- Linked templates (reference extraction)
- Copy loops
- Conditions
- Dependencies (dependsOn)

Reference:
https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/

## Contents

### Classes

- [ARMTemplateResource](#armtemplateresource)
- [ARMTemplateParser](#armtemplateparser)

### Functions

- [parse_arm_template_file](#parse_arm_template_file)
- [parse_arm_template_content](#parse_arm_template_content)

## Constants

### `ARM_RESOURCE_PREFIXES`

Type: `dict`

Value: `{'Microsoft.Storage/': 'azure_storage_', 'Microsoft.Compute/': 'azure_compute_', 'Microsoft.Network/': 'azure_network_', 'Microsoft.Web/': 'azure_web_', 'Microsoft.Sql/': 'azure_sql_', 'Microsoft.KeyVault/': 'azure_keyvault_', 'Microsoft.ContainerService/': 'azure_container_', 'Microsoft.ContainerRegistry/': 'azure_container_registry_', 'Microsoft.DocumentDB/': 'azure_cosmosdb_', 'Microsoft.EventHub/': 'azure_eventhub_', 'Microsoft.ServiceBus/': 'azure_servicebus_', 'Microsoft.Cache/': 'azure_cache_', 'Microsoft.Insights/': 'azure_monitor_', 'Microsoft.OperationalInsights/': 'azure_loganalytics_', 'Microsoft.Authorization/': 'azure_authorization_', 'Microsoft.ManagedIdentity/': 'azure_identity_', 'Microsoft.Resources/': 'azure_resources_', 'Microsoft.Security/': 'azure_security_'}`

## ARMTemplateResource

**Inherits from:** IaCResource

**Tags:** dataclass

An ARM template resource with additional metadata.

Extends IaCResource with ARM-specific attributes.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `api_version` | `str` | `` |
| `condition` | `str | None` | - |
| `copy` | `dict[(str, Any)] | None` | - |
| `comments` | `str | None` | - |
| `resource_group` | `str | None` | - |
| `subscription_id` | `str | None` | - |
| `scope` | `str | None` | - |
| `zones` | `list[str]` | `field(...)` |
| `sku` | `dict[(str, Any)] | None` | - |
| `kind` | `str | None` | - |
| `plan` | `dict[(str, Any)] | None` | - |
| `identity` | `dict[(str, Any)] | None` | - |
| `nested_resources` | `list[ARMTemplateResource]` | `field(...)` |

## ARMTemplateParser

**Inherits from:** IaCParser

Parser for Azure Resource Manager (ARM) templates.

Parses JSON format ARM templates and extracts resources,
parameters, variables, and other template components.

### Properties

#### `format(self) -> IaCFormat`

Return ARM format.

**Returns:**

`IaCFormat`

#### `file_extensions(self) -> list[str]`

Return ARM template file extensions.

**Returns:**

`list[str]`

### Methods

#### `parse_file(self, file_path: str | Path) -> IaCFile`

Parse an ARM template file.

**Parameters:**

- `file_path` (`str | Path`) - Path to the template file

**Returns:**

`IaCFile` - Parsed IaCFile object

#### `parse_content(self, content: str, file_path: str = <string>) -> IaCFile`

Parse ARM template content from a string.

**Parameters:**

- `content` (`str`) - The template content to parse
- `file_path` (`str`) - default: `<string>` - Virtual file path for error reporting

**Returns:**

`IaCFile` - Parsed IaCFile object

#### `can_parse(self, file_path: str | Path) -> bool`

Check if this parser can handle the given file.  Overridden to check file content for ARM template markers.

**Parameters:**

- `file_path` (`str | Path`)

**Returns:**

`bool`

### `parse_arm_template_file(file_path: str | Path) -> IaCFile`

Convenience function to parse a single ARM template.

**Parameters:**

- `file_path` (`str | Path`) - Path to the template file

**Returns:**

`IaCFile` - Parsed IaCFile object

### `parse_arm_template_content(content: str, file_path: str = <string>) -> IaCFile`

Convenience function to parse ARM template content.

**Parameters:**

- `content` (`str`) - Template content (JSON)
- `file_path` (`str`) - default: `<string>` - Virtual file path for error reporting

**Returns:**

`IaCFile` - Parsed IaCFile object
