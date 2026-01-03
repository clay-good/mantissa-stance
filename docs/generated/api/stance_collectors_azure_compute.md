# stance.collectors.azure_compute

Azure Compute collector for Mantissa Stance.

Collects Azure Virtual Machines, Network Security Groups, Virtual Networks,
and related network configuration for security posture assessment.

## Contents

### Classes

- [AzureComputeCollector](#azurecomputecollector)

## Constants

### `SENSITIVE_PORTS`

Type: `dict`

Value: `{22: 'SSH', 3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL', 1434: 'MSSQL Browser', 27017: 'MongoDB', 6379: 'Redis', 9200: 'Elasticsearch', 5601: 'Kibana', 8080: 'HTTP Alt', 23: 'Telnet', 21: 'FTP', 445: 'SMB', 135: 'RPC', 139: 'NetBIOS'}`

## AzureComputeCollector

**Inherits from:** BaseCollector

Collects Azure Compute resources and network configuration.

Gathers virtual machines, network security groups, virtual networks,
and subnets. All API calls are read-only.

### Properties

#### `subscription_id(self) -> str`

Get the Azure subscription ID.

**Returns:**

`str`

### Methods

#### `__init__(self, subscription_id: str, credential: Any | None, **kwargs: Any) -> None`

Initialize the Azure Compute collector.

**Parameters:**

- `subscription_id` (`str`) - Azure subscription ID to collect from.
- `credential` (`Any | None`) - Optional Azure credential object. **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

Collect all Compute and Network resources.

**Returns:**

`AssetCollection` - Collection of compute and network assets
