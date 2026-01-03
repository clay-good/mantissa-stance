# stance.collectors.azure_functions

Azure Functions collector for Mantissa Stance.

Collects Azure Function Apps and their security configurations
for security posture assessment.

## Contents

### Classes

- [AzureFunctionsCollector](#azurefunctionscollector)

## Constants

### `DEPRECATED_RUNTIMES`

Type: `str`

Value: `"Set(elts=[Constant(value='~1'), Constant(value='~2'), Constant(value='python|3.6'), Constant(value='python|3.7'), Constant(value='node|8'), Constant(value='node|10'), Constant(value='node|12'), Constant(value='dotnet|2.1'), Constant(value='dotnet|3.1'), Constant(value='java|8'), Constant(value='powershell|6')])"`

### `EOL_APPROACHING_RUNTIMES`

Type: `str`

Value: `"Set(elts=[Constant(value='~3'), Constant(value='python|3.8'), Constant(value='node|14'), Constant(value='node|16'), Constant(value='dotnet|5.0'), Constant(value='java|11'), Constant(value='powershell|7.0')])"`

## AzureFunctionsCollector

**Inherits from:** BaseCollector

Collects Azure Function App resources and configuration.

Gathers Function Apps with their security settings including:
- Runtime and deprecated runtime detection
- HTTPS-only configuration
- Authentication/authorization settings
- Network access restrictions (IP rules, VNet integration)
- Managed identity configuration
- App settings (names only, not values for security)
- TLS/SSL configuration
- CORS settings
- Slots and deployment configuration

All API calls are read-only.

### Properties

#### `subscription_id(self) -> str`

Get the Azure subscription ID.

**Returns:**

`str`

### Methods

#### `__init__(self, subscription_id: str, credential: Any | None, **kwargs: Any) -> None`

Initialize the Azure Functions collector.

**Parameters:**

- `subscription_id` (`str`) - Azure subscription ID to collect from.
- `credential` (`Any | None`) - Optional Azure credential object. **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

Collect all Azure Functions resources.

**Returns:**

`AssetCollection` - Collection of Azure Functions assets
