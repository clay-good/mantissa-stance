# stance.aggregation.sync

Cross-cloud synchronization for Mantissa Stance.

Provides synchronization of findings to central storage with support
for hub-and-spoke deployment models.

## Contents

### Classes

- [SyncDirection](#syncdirection)
- [ConflictResolution](#conflictresolution)
- [SyncConfig](#syncconfig)
- [SyncRecord](#syncrecord)
- [SyncResult](#syncresult)
- [StorageAdapter](#storageadapter)
- [CrossCloudSync](#crosscloudsync)
- [S3StorageAdapter](#s3storageadapter)
- [GCSStorageAdapter](#gcsstorageadapter)
- [AzureBlobStorageAdapter](#azureblobstorageadapter)

## SyncDirection

**Inherits from:** Enum

Direction of synchronization.

## ConflictResolution

**Inherits from:** Enum

Strategy for resolving sync conflicts.

## SyncConfig

**Tags:** dataclass

Configuration for cross-cloud synchronization.

Attributes:
    central_bucket: S3/GCS/ADLS bucket for central storage
    central_prefix: Prefix path in central storage
    sync_direction: Direction of synchronization
    conflict_resolution: Strategy for conflicts
    include_assets: Whether to sync assets (not just findings)
    batch_size: Number of records to sync per batch
    checksum_verify: Verify data integrity with checksums

### Attributes

| Name | Type | Default |
|------|------|---------|
| `central_bucket` | `str` | - |
| `central_prefix` | `str` | `aggregated` |
| `sync_direction` | `SyncDirection` | `"Attribute(value=Name(id='SyncDirection', ctx=Load()), attr='PUSH', ctx=Load())"` |
| `conflict_resolution` | `ConflictResolution` | `"Attribute(value=Name(id='ConflictResolution', ctx=Load()), attr='LATEST_WINS', ctx=Load())"` |
| `include_assets` | `bool` | `True` |
| `batch_size` | `int` | `1000` |
| `checksum_verify` | `bool` | `True` |

## SyncRecord

**Tags:** dataclass

Record of a synchronized item.

Attributes:
    id: Unique identifier of the record
    record_type: Type of record (finding, asset)
    source_account: Source cloud account
    source_provider: Source cloud provider
    synced_at: When the record was synced
    checksum: SHA256 checksum of the data
    version: Version number for optimistic locking

### Attributes

| Name | Type | Default |
|------|------|---------|
| `id` | `str` | - |
| `record_type` | `str` | - |
| `source_account` | `str` | - |
| `source_provider` | `str` | - |
| `synced_at` | `datetime` | - |
| `checksum` | `str` | - |
| `version` | `int` | `1` |

## SyncResult

**Tags:** dataclass

Result of a synchronization operation.

Attributes:
    success: Whether sync completed successfully
    records_synced: Number of records synchronized
    records_skipped: Number of records skipped (already synced)
    conflicts_resolved: Number of conflicts resolved
    errors: List of error messages
    duration_seconds: Time taken for sync
    sync_direction: Direction of sync

### Attributes

| Name | Type | Default |
|------|------|---------|
| `success` | `bool` | `True` |
| `records_synced` | `int` | `0` |
| `records_skipped` | `int` | `0` |
| `conflicts_resolved` | `int` | `0` |
| `errors` | `list[str]` | `field(...)` |
| `duration_seconds` | `float` | `0.0` |
| `sync_direction` | `SyncDirection` | `"Attribute(value=Name(id='SyncDirection', ctx=Load()), attr='PUSH', ctx=Load())"` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary representation.

**Returns:**

`dict[(str, Any)]`

## StorageAdapter

**Inherits from:** Protocol

Protocol for storage backends used in sync.

### Methods

#### `write_record(self, path: str, data: dict[(str, Any)]) -> None`

Write a record to storage.

**Parameters:**

- `path` (`str`)
- `data` (`dict[(str, Any)]`)

**Returns:**

`None`

#### `read_record(self, path: str) -> dict[(str, Any)] | None`

Read a record from storage.

**Parameters:**

- `path` (`str`)

**Returns:**

`dict[(str, Any)] | None`

#### `list_records(self, prefix: str) -> list[str]`

List record paths under a prefix.

**Parameters:**

- `prefix` (`str`)

**Returns:**

`list[str]`

#### `delete_record(self, path: str) -> None`

Delete a record from storage.

**Parameters:**

- `path` (`str`)

**Returns:**

`None`

#### `get_metadata(self, path: str) -> dict[(str, Any)] | None`

Get metadata for a record.

**Parameters:**

- `path` (`str`)

**Returns:**

`dict[(str, Any)] | None`

## CrossCloudSync

Synchronizes findings across cloud environments.

Supports hub-and-spoke model where multiple cloud accounts sync
their findings to a central storage location. Handles conflict
resolution and maintains data integrity.

Example:
    >>> config = SyncConfig(
    ...     central_bucket="stance-central-findings",
    ...     sync_direction=SyncDirection.PUSH
    ... )
    >>> sync = CrossCloudSync(config, storage_adapter)
    >>> sync.add_local_findings(findings, "123456789012", "aws")
    >>> result = sync.sync()
    >>> print(f"Synced {result.records_synced} records")

### Methods

#### `__init__(self, config: SyncConfig, storage: StorageAdapter) -> None`

Initialize the cross-cloud sync.

**Parameters:**

- `config` (`SyncConfig`) - Sync configuration
- `storage` (`StorageAdapter`) - Storage adapter for central storage

**Returns:**

`None`

#### `add_local_findings(self, findings: FindingCollection | list[Finding], account_id: str, provider: str) -> None`

Add local findings to be synced.

**Parameters:**

- `findings` (`FindingCollection | list[Finding]`) - Findings to sync
- `account_id` (`str`) - Source account identifier
- `provider` (`str`) - Cloud provider (aws, gcp, azure)

**Returns:**

`None`

#### `add_local_assets(self, assets: AssetCollection | list[Asset], account_id: str, provider: str) -> None`

Add local assets to be synced.

**Parameters:**

- `assets` (`AssetCollection | list[Asset]`) - Assets to sync
- `account_id` (`str`) - Source account identifier
- `provider` (`str`) - Cloud provider

**Returns:**

`None`

#### `sync(self) -> SyncResult`

Perform synchronization based on configured direction.

**Returns:**

`SyncResult` - SyncResult with sync statistics

#### `get_sync_state(self) -> dict[(str, SyncRecord)]`

Get current sync state.

**Returns:**

`dict[(str, SyncRecord)]`

#### `clear(self) -> None`

Clear local data and sync state.

**Returns:**

`None`

## S3StorageAdapter

S3 implementation of StorageAdapter protocol.

### Methods

#### `__init__(self, bucket: str, session: Any | None, region: str = us-east-1) -> None`

Initialize S3 adapter.

**Parameters:**

- `bucket` (`str`)
- `session` (`Any | None`)
- `region` (`str`) - default: `us-east-1`

**Returns:**

`None`

#### `write_record(self, path: str, data: dict[(str, Any)]) -> None`

Write a record to S3.

**Parameters:**

- `path` (`str`)
- `data` (`dict[(str, Any)]`)

**Returns:**

`None`

#### `read_record(self, path: str) -> dict[(str, Any)] | None`

Read a record from S3.

**Parameters:**

- `path` (`str`)

**Returns:**

`dict[(str, Any)] | None`

#### `list_records(self, prefix: str) -> list[str]`

List record paths under a prefix.

**Parameters:**

- `prefix` (`str`)

**Returns:**

`list[str]`

#### `delete_record(self, path: str) -> None`

Delete a record from S3.

**Parameters:**

- `path` (`str`)

**Returns:**

`None`

#### `get_metadata(self, path: str) -> dict[(str, Any)] | None`

Get metadata for a record.

**Parameters:**

- `path` (`str`)

**Returns:**

`dict[(str, Any)] | None`

## GCSStorageAdapter

Google Cloud Storage implementation of StorageAdapter protocol.

### Methods

#### `__init__(self, bucket: str, credentials: Any | None) -> None`

Initialize GCS adapter.

**Parameters:**

- `bucket` (`str`)
- `credentials` (`Any | None`)

**Returns:**

`None`

#### `write_record(self, path: str, data: dict[(str, Any)]) -> None`

Write a record to GCS.

**Parameters:**

- `path` (`str`)
- `data` (`dict[(str, Any)]`)

**Returns:**

`None`

#### `read_record(self, path: str) -> dict[(str, Any)] | None`

Read a record from GCS.

**Parameters:**

- `path` (`str`)

**Returns:**

`dict[(str, Any)] | None`

#### `list_records(self, prefix: str) -> list[str]`

List record paths under a prefix.

**Parameters:**

- `prefix` (`str`)

**Returns:**

`list[str]`

#### `delete_record(self, path: str) -> None`

Delete a record from GCS.

**Parameters:**

- `path` (`str`)

**Returns:**

`None`

#### `get_metadata(self, path: str) -> dict[(str, Any)] | None`

Get metadata for a record.

**Parameters:**

- `path` (`str`)

**Returns:**

`dict[(str, Any)] | None`

## AzureBlobStorageAdapter

Azure Blob Storage implementation of StorageAdapter protocol.

### Methods

#### `__init__(self, account_name: str, container: str, credential: Any | None) -> None`

Initialize Azure Blob adapter.

**Parameters:**

- `account_name` (`str`)
- `container` (`str`)
- `credential` (`Any | None`)

**Returns:**

`None`

#### `write_record(self, path: str, data: dict[(str, Any)]) -> None`

Write a record to Azure Blob Storage.

**Parameters:**

- `path` (`str`)
- `data` (`dict[(str, Any)]`)

**Returns:**

`None`

#### `read_record(self, path: str) -> dict[(str, Any)] | None`

Read a record from Azure Blob Storage.

**Parameters:**

- `path` (`str`)

**Returns:**

`dict[(str, Any)] | None`

#### `list_records(self, prefix: str) -> list[str]`

List record paths under a prefix.

**Parameters:**

- `prefix` (`str`)

**Returns:**

`list[str]`

#### `delete_record(self, path: str) -> None`

Delete a record from Azure Blob Storage.

**Parameters:**

- `path` (`str`)

**Returns:**

`None`

#### `get_metadata(self, path: str) -> dict[(str, Any)] | None`

Get metadata for a record.

**Parameters:**

- `path` (`str`)

**Returns:**

`dict[(str, Any)] | None`
