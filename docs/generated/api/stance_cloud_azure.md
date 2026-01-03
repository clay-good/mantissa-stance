# stance.cloud.azure

Microsoft Azure provider implementation.

This module provides Azure-specific implementation of the CloudProvider
interface, using the Azure SDK for Python.

## Contents

### Classes

- [AzureProvider](#azureprovider)

## AzureProvider

**Inherits from:** CloudProvider

Microsoft Azure provider implementation.

Uses Azure SDK for Python for all Azure API interactions. Supports
service principal authentication and Azure CLI credentials.

### Properties

#### `provider_name(self) -> str`

**Returns:**

`str`

#### `display_name(self) -> str`

**Returns:**

`str`

#### `subscription_id(self) -> str`

Get the Azure subscription ID.

**Returns:**

`str`

### Methods

#### `__init__(self, credentials: CloudCredentials | None, subscription_id: str | None, region: str = eastus, **kwargs: Any) -> None`

Initialize Azure provider.

**Parameters:**

- `credentials` (`CloudCredentials | None`) - Optional credentials with Azure service principal.
- `subscription_id` (`str | None`) - Azure subscription ID. Required.
- `region` (`str`) - default: `eastus` - Default Azure region. **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `initialize(self) -> None`

Initialize Azure credentials and validate subscription.

**Returns:**

`None`

#### `validate_credentials(self) -> bool`

Validate Azure credentials.

**Returns:**

`bool`

#### `get_account(self) -> CloudAccount`

Get Azure subscription information.

**Returns:**

`CloudAccount`

#### `list_regions(self) -> list[CloudRegion]`

List available Azure regions.

**Returns:**

`list[CloudRegion]`

#### `get_collectors(self) -> list[BaseCollector]`

Get Azure collectors.

**Returns:**

`list[BaseCollector]`

#### `get_storage_backend(self, storage_type: str = blob, **kwargs: Any) -> StorageBackend`

Get Azure storage backend (Blob Storage).

**Parameters:**

- `storage_type` (`str`) - default: `blob`
- `**kwargs` (`Any`)

**Returns:**

`StorageBackend`

#### `get_credential(self)`

Get the Azure credential for direct use.

### Class Methods

#### `is_available(cls) -> bool`

**Decorators:** @classmethod

Check if Azure SDK is installed.

**Returns:**

`bool`

#### `get_required_packages(cls) -> list[str]`

**Decorators:** @classmethod

**Returns:**

`list[str]`
