# stance.storage.gcs

Google Cloud Storage based storage implementation.

This module provides GCSStorage, a storage backend that stores assets
and findings in Google Cloud Storage with support for BigQuery querying.

## Contents

### Classes

- [GCSStorage](#gcsstorage)

## GCSStorage

**Inherits from:** StorageBackend

Google Cloud Storage based storage for production deployments.

Stores assets and findings as JSON files in GCS, organized by snapshot ID.
The format is compatible with BigQuery for SQL querying.

Attributes:
    bucket: GCS bucket name
    prefix: Key prefix for all stored objects
    project_id: GCP project ID

### Methods

#### `__init__(self, bucket: str, prefix: str = stance, project_id: str | None, credentials: Any) -> None`

Initialize the GCS storage backend.

**Parameters:**

- `bucket` (`str`) - GCS bucket name for storage
- `prefix` (`str`) - default: `stance` - Key prefix for all objects (default: "stance")
- `project_id` (`str | None`) - GCP project ID
- `credentials` (`Any`) - Optional google.auth credentials object

**Returns:**

`None`

**Raises:**

- `ImportError`: If google-cloud-storage is not installed

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

#### `get_bigquery_table_ddl(self, table_type: str = assets) -> str`

Get BigQuery CREATE TABLE statement for querying data.

**Parameters:**

- `table_type` (`str`) - default: `assets` - Either "assets" or "findings"

**Returns:**

`str` - CREATE EXTERNAL TABLE statement for BigQuery

#### `delete_snapshot(self, snapshot_id: str) -> bool`

Delete a snapshot and all associated data.

**Parameters:**

- `snapshot_id` (`str`)

**Returns:**

`bool`
