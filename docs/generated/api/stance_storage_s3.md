# stance.storage.s3

S3-based storage implementation for production deployments.

This module provides S3Storage, a storage backend that stores assets
and findings in Amazon S3 with support for Athena querying.

## Contents

### Classes

- [S3Storage](#s3storage)

## S3Storage

**Inherits from:** StorageBackend

S3-based storage for production deployments with Athena querying.

Stores assets and findings as JSON files in S3, organized by snapshot ID.
The format is compatible with Athena for SQL querying.

Attributes:
    bucket: S3 bucket name
    prefix: Key prefix for all stored objects
    region: AWS region

### Methods

#### `__init__(self, bucket: str, prefix: str = stance, region: str = us-east-1) -> None`

Initialize the S3 storage backend.

**Parameters:**

- `bucket` (`str`) - S3 bucket name for storage
- `prefix` (`str`) - default: `stance` - Key prefix for all objects (default: "stance")
- `region` (`str`) - default: `us-east-1` - AWS region (default: "us-east-1")

**Returns:**

`None`

**Raises:**

- `ImportError`: If boto3 is not installed

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

- `snapshot_id` (`str`) - The snapshot to get info for

**Returns:**

`dict[(str, Any)] | None` - Dictionary with snapshot metadata, or None if not found

#### `get_athena_table_ddl(self, table_type: str = assets) -> str`

Get Athena CREATE TABLE statement for querying data.

**Parameters:**

- `table_type` (`str`) - default: `assets` - Either "assets" or "findings"

**Returns:**

`str` - CREATE EXTERNAL TABLE statement for Athena

#### `delete_snapshot(self, snapshot_id: str) -> bool`

Delete a snapshot and all associated data.

**Parameters:**

- `snapshot_id` (`str`) - Snapshot to delete

**Returns:**

`bool` - True if snapshot was deleted, False if not found
