# stance.collectors.azure_sql

Azure SQL Database collector for Mantissa Stance.

Collects Azure SQL servers, databases, and their security configurations
for security posture assessment.

## Contents

### Classes

- [AzureSQLCollector](#azuresqlcollector)

## AzureSQLCollector

**Inherits from:** BaseCollector

Collects Azure SQL Database resources and configuration.

Gathers SQL servers, databases, firewall rules, encryption settings,
auditing configuration, and vulnerability assessments. All API calls
are read-only.

### Properties

#### `subscription_id(self) -> str`

Get the Azure subscription ID.

**Returns:**

`str`

### Methods

#### `__init__(self, subscription_id: str, credential: Any | None, **kwargs: Any) -> None`

Initialize the Azure SQL collector.

**Parameters:**

- `subscription_id` (`str`) - Azure subscription ID to collect from.
- `credential` (`Any | None`) - Optional Azure credential object. **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

Collect all Azure SQL resources.

**Returns:**

`AssetCollection` - Collection of Azure SQL assets
