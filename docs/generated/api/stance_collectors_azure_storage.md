# stance.collectors.azure_storage

Azure Storage collector for Mantissa Stance.

Collects Azure Storage account configurations including blob containers,
access policies, encryption settings, and network rules for security posture assessment.

## Contents

### Classes

- [AzureStorageCollector](#azurestoragecollector)

## AzureStorageCollector

**Inherits from:** BaseCollector

Collects Azure Storage account resources and configuration.

Gathers storage accounts, blob containers, access policies,
encryption settings, and network rules. All API calls are read-only.

### Properties

#### `subscription_id(self) -> str`

Get the Azure subscription ID.

**Returns:**

`str`

### Methods

#### `__init__(self, subscription_id: str, credential: Any | None, **kwargs: Any) -> None`

Initialize the Azure Storage collector.

**Parameters:**

- `subscription_id` (`str`) - Azure subscription ID to collect from.
- `credential` (`Any | None`) - Optional Azure credential object. **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

Collect all Storage resources.

**Returns:**

`AssetCollection` - Collection of storage assets
