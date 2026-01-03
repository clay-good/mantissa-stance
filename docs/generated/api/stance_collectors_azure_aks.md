# stance.collectors.azure_aks

Azure Kubernetes Service (AKS) collector for Mantissa Stance.

Collects Azure AKS clusters, node pools, and security configurations
for posture assessment. Covers Azure AD integration, network policies,
managed identity, and Kubernetes RBAC settings.

## Contents

### Classes

- [AzureAKSCollector](#azureakscollector)

## AzureAKSCollector

**Inherits from:** BaseCollector

Collects Azure Kubernetes Service resources and configuration.

Gathers AKS clusters, agent pools (node pools), and their security
configurations including Azure AD integration, network policies,
managed identity settings, and RBAC. All API calls are read-only.

### Properties

#### `subscription_id(self) -> str`

Get the Azure subscription ID.

**Returns:**

`str`

### Methods

#### `__init__(self, subscription_id: str, credential: Any | None, **kwargs: Any) -> None`

Initialize the Azure AKS collector.

**Parameters:**

- `subscription_id` (`str`) - Azure subscription ID to collect from.
- `credential` (`Any | None`) - Optional Azure credential object. **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

Collect all Azure AKS resources.

**Returns:**

`AssetCollection` - Collection of AKS cluster and node pool assets
