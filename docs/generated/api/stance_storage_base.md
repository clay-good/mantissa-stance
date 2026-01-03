# stance.storage.base

Abstract base class for storage backends.

This module defines the StorageBackend interface that all storage
implementations must follow, along with utility functions for
snapshot ID generation.

## Contents

### Classes

- [StorageBackend](#storagebackend)

### Functions

- [generate_snapshot_id](#generate_snapshot_id)

## StorageBackend

**Inherits from:** ABC

Abstract base class for storage implementations.

All storage backends must implement these methods to provide
consistent storage and retrieval of assets and findings.

### Methods

#### `store_assets(self, assets: AssetCollection, snapshot_id: str) -> None`

**Decorators:** @abstractmethod

Store an asset inventory snapshot.

**Parameters:**

- `assets` (`AssetCollection`) - Collection of assets to store
- `snapshot_id` (`str`) - Unique identifier for this snapshot

**Returns:**

`None`

#### `store_findings(self, findings: FindingCollection, snapshot_id: str) -> None`

**Decorators:** @abstractmethod

Store findings from policy evaluation.

**Parameters:**

- `findings` (`FindingCollection`) - Collection of findings to store
- `snapshot_id` (`str`) - Unique identifier for this snapshot

**Returns:**

`None`

#### `get_assets(self, snapshot_id: str | None) -> AssetCollection`

**Decorators:** @abstractmethod

Retrieve assets from storage.

**Parameters:**

- `snapshot_id` (`str | None`) - Snapshot to retrieve. If None, returns latest.

**Returns:**

`AssetCollection` - Collection of assets from the specified snapshot

#### `get_findings(self, snapshot_id: str | None, severity: Severity | None, status: FindingStatus | None) -> FindingCollection`

**Decorators:** @abstractmethod

Retrieve findings from storage with optional filters.

**Parameters:**

- `snapshot_id` (`str | None`) - Snapshot to retrieve. If None, returns latest.
- `severity` (`Severity | None`) - Filter by severity level
- `status` (`FindingStatus | None`) - Filter by finding status

**Returns:**

`FindingCollection` - Collection of findings matching the criteria

#### `get_latest_snapshot_id(self) -> str | None`

**Decorators:** @abstractmethod

Get the most recent snapshot ID.

**Returns:**

`str | None` - Latest snapshot ID, or None if no snapshots exist

#### `list_snapshots(self, limit: int = 10) -> list[str]`

**Decorators:** @abstractmethod

List recent snapshot IDs.

**Parameters:**

- `limit` (`int`) - default: `10` - Maximum number of snapshots to return

**Returns:**

`list[str]` - List of snapshot IDs, most recent first

#### `create_snapshot(self, assets: AssetCollection, findings: FindingCollection, snapshot_id: str | None) -> str`

Create a new snapshot with assets and findings.  This is a convenience method that stores both assets and findings with the same snapshot ID.

**Parameters:**

- `assets` (`AssetCollection`) - Collection of assets to store
- `findings` (`FindingCollection`) - Collection of findings to store
- `snapshot_id` (`str | None`) - Optional snapshot ID. If None, generates one.

**Returns:**

`str` - The snapshot ID used

### `generate_snapshot_id() -> str`

Generate a timestamp-based snapshot ID.

**Returns:**

`str` - Snapshot ID in format YYYYMMDD-HHMMSS
