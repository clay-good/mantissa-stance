# stance.dspm.cost.azure_cost

Azure Blob Storage Cost Analyzer for DSPM.

Analyzes Azure Blob Storage container costs and identifies cold data
that can be archived or deleted to save costs.

## Contents

### Classes

- [AzureCostAnalyzer](#azurecostanalyzer)

## Constants

### `AZURE_ACCESS_TIER_MAP`

Type: `dict`

Value: `{'Hot': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'AZURE_HOT\', ctx=Load())"', 'Cool': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'AZURE_COOL\', ctx=Load())"', 'Cold': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'AZURE_COLD\', ctx=Load())"', 'Archive': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'AZURE_ARCHIVE\', ctx=Load())"'}`

## AzureCostAnalyzer

**Inherits from:** BaseCostAnalyzer

Azure Blob Storage cost analyzer.

Analyzes Azure Blob containers to identify cold data and estimate storage costs.
Uses blob metadata and last access time (if available) for analysis.

All operations are read-only.

### Methods

#### `__init__(self, config: CostAnalysisConfig | None, connection_string: str | None, account_url: str | None, credential: Any | None)`

Initialize Azure cost analyzer.

**Parameters:**

- `config` (`CostAnalysisConfig | None`) - Optional cost analysis configuration
- `connection_string` (`str | None`) - Azure Storage connection string
- `account_url` (`str | None`) - Storage account URL (https://<account>.blob.core.windows.net)
- `credential` (`Any | None`) - Optional credential object

#### `analyze_bucket(self, bucket_name: str) -> CostAnalysisResult`

Analyze an Azure Blob container for cost optimization opportunities.

**Parameters:**

- `bucket_name` (`str`) - Name of the container (with or without azure:// prefix)

**Returns:**

`CostAnalysisResult` - Cost analysis result with findings and metrics

#### `get_storage_metrics(self, bucket_name: str) -> StorageMetrics`

Get storage metrics for an Azure Blob container.

**Parameters:**

- `bucket_name` (`str`) - Name of the container

**Returns:**

`StorageMetrics` - Storage metrics including size, object count, costs

#### `get_object_access_info(self, bucket_name: str, object_key: str) -> ObjectAccessInfo | None`

Get access information for a specific Azure blob.  Azure Blob Storage can track last access time if enabled on the account. Otherwise, we use last modified time as a proxy.

**Parameters:**

- `bucket_name` (`str`) - Name of the container
- `object_key` (`str`) - Blob name

**Returns:**

`ObjectAccessInfo | None` - Object access information or None if not found

#### `list_objects_with_access_info(self, bucket_name: str, prefix: str = ) -> Iterator[ObjectAccessInfo]`

List blobs with access information.

**Parameters:**

- `bucket_name` (`str`) - Name of the container
- `prefix` (`str`) - default: `` - Optional prefix filter

**Returns:**

`Iterator[ObjectAccessInfo]`

#### `get_lifecycle_management_policy(self, container_name: str) -> dict[(str, Any)] | None`

Get lifecycle management policy for the storage account.  Note: Lifecycle policies are set at the storage account level in Azure, not per container.

**Parameters:**

- `container_name` (`str`) - Name of the container (unused, kept for API consistency)

**Returns:**

`dict[(str, Any)] | None` - Lifecycle management policy or None

#### `list_containers(self) -> Iterator[str]`

List all containers in the storage account.  Yields: Container names

**Returns:**

`Iterator[str]`

#### `get_account_info(self) -> dict[(str, Any)]`

Get storage account information.

**Returns:**

`dict[(str, Any)]` - Account information dictionary
