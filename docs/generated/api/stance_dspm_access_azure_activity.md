# stance.dspm.access.azure_activity

Azure Activity Log Access Analyzer for DSPM.

Analyzes Azure Activity Logs to detect stale Blob Storage access patterns
and identify unused or over-privileged permissions.

## Contents

### Classes

- [AzureActivityLogAnalyzer](#azureactivityloganalyzer)

## Constants

### `AZURE_ACTION_MAPPING`

Type: `dict`

Value: `{'GetBlob': 'read', 'GetBlobProperties': 'read', 'GetBlobMetadata': 'read', 'HeadBlob': 'read', 'ListBlobs': 'list', 'ListContainers': 'list', 'PutBlob': 'write', 'PutBlockList': 'write', 'PutBlock': 'write', 'CopyBlob': 'write', 'SetBlobProperties': 'write', 'SetBlobMetadata': 'write', 'DeleteBlob': 'delete', 'DeleteContainer': 'delete', 'SetContainerAcl': 'admin', 'SetBlobTier': 'write'}`

## AzureActivityLogAnalyzer

**Inherits from:** BaseAccessAnalyzer

Azure Activity Log analyzer for Blob Storage access patterns.

Queries Azure Activity Logs and Storage Analytics to identify:
- Stale access (permissions not used in X days)
- Unused permissions (no access recorded)
- Over-privileged access (write permissions but only reads)

All operations are read-only.

### Methods

#### `__init__(self, config: AccessReviewConfig | None, subscription_id: str | None, credential: Any | None, resource_group: str | None, storage_account: str | None)`

Initialize Azure Activity Log analyzer.

**Parameters:**

- `config` (`AccessReviewConfig | None`) - Optional access review configuration
- `subscription_id` (`str | None`) - Azure subscription ID
- `credential` (`Any | None`) - Optional Azure credential object
- `resource_group` (`str | None`) - Resource group name
- `storage_account` (`str | None`) - Storage account name

#### `analyze_resource(self, resource_id: str) -> AccessReviewResult`

Analyze access patterns for an Azure Blob container.

**Parameters:**

- `resource_id` (`str`) - Container name or full resource path

**Returns:**

`AccessReviewResult` - Access review result with findings

#### `get_access_events(self, resource_id: str, start_time: datetime, end_time: datetime) -> Iterator[AccessEvent]`

Retrieve Blob Storage access events from Azure Activity Logs.

**Parameters:**

- `resource_id` (`str`) - Container name
- `start_time` (`datetime`) - Start of time range
- `end_time` (`datetime`) - End of time range

**Returns:**

`Iterator[AccessEvent]`

#### `get_resource_permissions(self, resource_id: str) -> dict[(str, dict[(str, Any)])]`

Get current permissions for an Azure Blob container.  Analyzes storage account role assignments.

**Parameters:**

- `resource_id` (`str`) - Container name

**Returns:**

`dict[(str, dict[(str, Any)])]` - Dictionary mapping principal_id to permission details

#### `get_storage_account_info(self) -> dict[(str, Any)]`

Get storage account information.

**Returns:**

`dict[(str, Any)]`

#### `list_containers(self) -> Iterator[dict[(str, Any)]]`

List all containers in the storage account.

**Returns:**

`Iterator[dict[(str, Any)]]`
