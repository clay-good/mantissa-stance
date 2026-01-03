# stance.collectors.azure_iam

Azure IAM collector for Mantissa Stance.

Collects Azure identity resources including role assignments, service principals,
managed identities, and Azure AD configurations for security posture assessment.

## Contents

### Classes

- [AzureIAMCollector](#azureiamcollector)

## AzureIAMCollector

**Inherits from:** BaseCollector

Collects Azure IAM resources and configuration.

Gathers role assignments, role definitions, service principals,
and managed identities. All API calls are read-only.

### Properties

#### `subscription_id(self) -> str`

Get the Azure subscription ID.

**Returns:**

`str`

### Methods

#### `__init__(self, subscription_id: str, credential: Any | None, **kwargs: Any) -> None`

Initialize the Azure IAM collector.

**Parameters:**

- `subscription_id` (`str`) - Azure subscription ID to collect from.
- `credential` (`Any | None`) - Optional Azure credential object. **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

Collect all IAM resources.

**Returns:**

`AssetCollection` - Collection of IAM assets
