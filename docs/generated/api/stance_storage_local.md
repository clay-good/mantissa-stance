# stance.storage.local

SQLite-based local storage implementation.

This module provides LocalStorage, a SQLite-based storage backend
suitable for development and single-user scenarios.

## Contents

### Classes

- [LocalStorage](#localstorage)

## LocalStorage

**Inherits from:** StorageBackend

SQLite-based local storage for development and single-user scenarios.

Stores assets and findings in a local SQLite database with support
for snapshots and basic querying.

Attributes:
    db_path: Path to the SQLite database file

### Methods

#### `__init__(self, db_path: str = ~/.stance/stance.db) -> None`

Initialize the local storage backend.  Creates the database directory and file if they don't exist, and initializes the database schema.

**Parameters:**

- `db_path` (`str`) - default: `~/.stance/stance.db` - Path to the SQLite database file. Supports ~ for home directory.

**Returns:**

`None`

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

#### `query_assets(self, sql: str) -> list[dict[(str, Any)]]`

Execute a raw SQL query against the assets table.  Only SELECT queries are allowed for security.

**Parameters:**

- `sql` (`str`) - SQL query string (must be SELECT only)

**Returns:**

`list[dict[(str, Any)]]` - List of result dictionaries

**Raises:**

- `ValueError`: If query is not a SELECT statement

#### `query_findings(self, sql: str) -> list[dict[(str, Any)]]`

Execute a raw SQL query against the findings table.  Only SELECT queries are allowed for security.

**Parameters:**

- `sql` (`str`) - SQL query string (must be SELECT only)

**Returns:**

`list[dict[(str, Any)]]` - List of result dictionaries

**Raises:**

- `ValueError`: If query is not a SELECT statement

#### `delete_snapshot(self, snapshot_id: str) -> bool`

Delete a snapshot and all associated data.

**Parameters:**

- `snapshot_id` (`str`) - Snapshot to delete

**Returns:**

`bool` - True if snapshot was deleted, False if not found
