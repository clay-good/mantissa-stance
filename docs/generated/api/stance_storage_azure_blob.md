# stance.storage.azure_blob

Azure Blob Storage based storage implementation.

This module provides AzureBlobStorage, a storage backend that stores assets
and findings in Azure Blob Storage with support for Azure Synapse querying.

## Contents

### Classes

- [AzureBlobStorage](#azureblobstorage)

## AzureBlobStorage

**Inherits from:** StorageBackend

Azure Blob Storage based storage for production deployments.

Stores assets and findings as JSON files in Azure Blob Storage,
organized by snapshot ID. The format is compatible with Azure Synapse
for SQL querying.

Attributes:
    account_name: Azure Storage account name
    container: Container name for storage
    prefix: Blob prefix for all stored objects

### Methods

#### `__init__(self, account_name: str, container: str, prefix: str = stance, credential: Any, connection_string: str | None) -> None`

Initialize the Azure Blob storage backend.

**Parameters:**

- `account_name` (`str`) - Azure Storage account name
- `container` (`str`) - Container name for storage
- `prefix` (`str`) - default: `stance` - Blob prefix for all objects (default: "stance")
- `credential` (`Any`) - Azure credential object (from azure.identity)
- `connection_string` (`str | None`) - Optional connection string (alternative to credential)

**Returns:**

`None`

**Raises:**

- `ImportError`: If azure-storage-blob is not installed

#### `store_assets(self, assets: AssetCollection, snapshot_id: str) -> None`

Store an asset inventory snapshot.

**Parameters:**

- `assets` (`AssetCollection`)
- `snapshot_id` (`str`)

**Returns:**

`None`

#### `store_findings(self, findings: FindingCollection, snapshot_id: str) -> None`

Store findings from policy evaluation.

**Parameters:**

- `findings` (`FindingCollection`)
- `snapshot_id` (`str`)

**Returns:**

`None`

#### `get_assets(self, snapshot_id: str | None) -> AssetCollection`

Retrieve assets from storage.

**Parameters:**

- `snapshot_id` (`str | None`)

**Returns:**

`AssetCollection`

#### `get_findings(self, snapshot_id: str | None, severity: Severity | None, status: FindingStatus | None) -> FindingCollection`

Retrieve findings from storage with optional filters.

**Parameters:**

- `snapshot_id` (`str | None`)
- `severity` (`Severity | None`)
- `status` (`FindingStatus | None`)

**Returns:**

`FindingCollection`

#### `get_latest_snapshot_id(self) -> str | None`

Get the most recent snapshot ID.

**Returns:**

`str | None`

#### `list_snapshots(self, limit: int = 10) -> list[str]`

List recent snapshot IDs.

**Parameters:**

- `limit` (`int`) - default: `10`

**Returns:**

`list[str]`

#### `get_snapshot_info(self, snapshot_id: str) -> dict[(str, Any)] | None`

Get information about a specific snapshot.

**Parameters:**

- `snapshot_id` (`str`)

**Returns:**

`dict[(str, Any)] | None`

#### `get_synapse_table_ddl(self, table_type: str = assets) -> str`

Get Azure Synapse CREATE TABLE statement for querying data.

**Parameters:**

- `table_type` (`str`) - default: `assets` - Either "assets" or "findings"

**Returns:**

`str` - CREATE EXTERNAL TABLE statement for Synapse

#### `delete_snapshot(self, snapshot_id: str) -> bool`

Delete a snapshot and all associated data.

**Parameters:**

- `snapshot_id` (`str`)

**Returns:**

`bool`
