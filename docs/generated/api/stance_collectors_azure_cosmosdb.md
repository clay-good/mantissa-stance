# stance.collectors.azure_cosmosdb

Azure Cosmos DB collector for Mantissa Stance.

Collects Azure Cosmos DB accounts, databases, and their security configurations
for security posture assessment.

## Contents

### Classes

- [AzureCosmosDBCollector](#azurecosmosdbcollector)

## AzureCosmosDBCollector

**Inherits from:** BaseCollector

Collects Azure Cosmos DB resources and configuration.

Gathers Cosmos DB accounts with their security settings including:
- Network access controls (firewall, VNet, private endpoints)
- Encryption configuration (service-managed vs customer-managed keys)
- Authentication and RBAC settings
- Backup policies
- Consistency levels and replication

All API calls are read-only.

### Properties

#### `subscription_id(self) -> str`

Get the Azure subscription ID.

**Returns:**

`str`

### Methods

#### `__init__(self, subscription_id: str, credential: Any | None, **kwargs: Any) -> None`

Initialize the Azure Cosmos DB collector.

**Parameters:**

- `subscription_id` (`str`) - Azure subscription ID to collect from.
- `credential` (`Any | None`) - Optional Azure credential object. **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

Collect all Azure Cosmos DB resources.

**Returns:**

`AssetCollection` - Collection of Azure Cosmos DB assets
