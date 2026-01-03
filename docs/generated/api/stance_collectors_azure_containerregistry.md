# stance.collectors.azure_containerregistry

Azure Container Registry collector for Mantissa Stance.

Collects Azure Container Registry (ACR) repositories, images, and their
security configurations for posture assessment. Supports vulnerability
scanning results from Microsoft Defender for Containers.

## Contents

### Classes

- [AzureContainerRegistryCollector](#azurecontainerregistrycollector)

## AzureContainerRegistryCollector

**Inherits from:** BaseCollector

Collects Azure Container Registry resources and configuration.

Gathers ACR registries, repositories, images, security settings,
and vulnerability scan results. All API calls are read-only.

### Properties

#### `subscription_id(self) -> str`

Get the Azure subscription ID.

**Returns:**

`str`

### Methods

#### `__init__(self, subscription_id: str, credential: Any | None, **kwargs: Any) -> None`

Initialize the Azure Container Registry collector.

**Parameters:**

- `subscription_id` (`str`) - Azure subscription ID to collect from.
- `credential` (`Any | None`) - Optional Azure credential object. **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

Collect all Azure Container Registry resources.

**Returns:**

`AssetCollection` - Collection of ACR assets

#### `collect_findings(self) -> FindingCollection`

Collect vulnerability findings from container image scans.  Note: Vulnerability scanning requires Microsoft Defender for Containers to be enabled on the subscription.

**Returns:**

`FindingCollection` - Collection of vulnerability findings from image scans
