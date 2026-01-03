# stance.state.state_manager

State management for Mantissa Stance.

Provides state tracking for scans, checkpoints, and finding lifecycle.
Supports multiple backends: local file, DynamoDB, Firestore, and Cosmos DB.

## Contents

### Classes

- [ScanStatus](#scanstatus)
- [FindingLifecycle](#findinglifecycle)
- [ScanRecord](#scanrecord)
- [Checkpoint](#checkpoint)
- [FindingState](#findingstate)
- [StateBackend](#statebackend)
- [LocalStateBackend](#localstatebackend)
- [StateManager](#statemanager)

### Functions

- [get_state_manager](#get_state_manager)

## ScanStatus

**Inherits from:** Enum

Status of a scan operation.

## FindingLifecycle

**Inherits from:** Enum

Lifecycle states for findings.

## ScanRecord

**Tags:** dataclass

Record of a scan execution.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `scan_id` | `str` | - |
| `snapshot_id` | `str` | - |
| `status` | `ScanStatus` | - |
| `started_at` | `datetime` | - |
| `completed_at` | `datetime | None` | - |
| `config_name` | `str` | `default` |
| `account_id` | `str` | `` |
| `region` | `str` | `` |
| `collectors` | `list[str]` | `field(...)` |
| `asset_count` | `int` | `0` |
| `finding_count` | `int` | `0` |
| `error_message` | `str` | `` |
| `duration_seconds` | `float` | `0.0` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> ScanRecord`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)

**Returns:**

`ScanRecord`

## Checkpoint

**Tags:** dataclass

Checkpoint for incremental scans.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `checkpoint_id` | `str` | - |
| `collector_name` | `str` | - |
| `account_id` | `str` | - |
| `region` | `str` | - |
| `last_scan_id` | `str` | - |
| `last_scan_time` | `datetime` | - |
| `cursor` | `str` | `` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> Checkpoint`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)

**Returns:**

`Checkpoint`

## FindingState

**Tags:** dataclass

State tracking for a finding.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding_id` | `str` | - |
| `asset_id` | `str` | - |
| `rule_id` | `str` | - |
| `lifecycle` | `FindingLifecycle` | - |
| `first_seen` | `datetime` | - |
| `last_seen` | `datetime` | - |
| `resolved_at` | `datetime | None` | - |
| `scan_count` | `int` | `1` |
| `suppressed_by` | `str` | `` |
| `suppressed_at` | `datetime | None` | - |
| `suppression_reason` | `str` | `` |
| `notes` | `list[str]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> FindingState`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)

**Returns:**

`FindingState`

## StateBackend

**Inherits from:** ABC

Abstract base class for state storage backends.

### Methods

#### `save_scan(self, record: ScanRecord) -> None`

**Decorators:** @abstractmethod

Save a scan record.

**Parameters:**

- `record` (`ScanRecord`)

**Returns:**

`None`

#### `get_scan(self, scan_id: str) -> ScanRecord | None`

**Decorators:** @abstractmethod

Get a scan record by ID.

**Parameters:**

- `scan_id` (`str`)

**Returns:**

`ScanRecord | None`

#### `list_scans(self, limit: int = 100, status: ScanStatus | None, since: datetime | None) -> list[ScanRecord]`

**Decorators:** @abstractmethod

List scan records with optional filters.

**Parameters:**

- `limit` (`int`) - default: `100`
- `status` (`ScanStatus | None`)
- `since` (`datetime | None`)

**Returns:**

`list[ScanRecord]`

#### `save_checkpoint(self, checkpoint: Checkpoint) -> None`

**Decorators:** @abstractmethod

Save a checkpoint.

**Parameters:**

- `checkpoint` (`Checkpoint`)

**Returns:**

`None`

#### `get_checkpoint(self, collector_name: str, account_id: str, region: str) -> Checkpoint | None`

**Decorators:** @abstractmethod

Get a checkpoint for a collector/account/region combination.

**Parameters:**

- `collector_name` (`str`)
- `account_id` (`str`)
- `region` (`str`)

**Returns:**

`Checkpoint | None`

#### `delete_checkpoint(self, collector_name: str, account_id: str, region: str) -> bool`

**Decorators:** @abstractmethod

Delete a checkpoint.

**Parameters:**

- `collector_name` (`str`)
- `account_id` (`str`)
- `region` (`str`)

**Returns:**

`bool`

#### `save_finding_state(self, state: FindingState) -> None`

**Decorators:** @abstractmethod

Save finding state.

**Parameters:**

- `state` (`FindingState`)

**Returns:**

`None`

#### `get_finding_state(self, finding_id: str) -> FindingState | None`

**Decorators:** @abstractmethod

Get finding state by ID.

**Parameters:**

- `finding_id` (`str`)

**Returns:**

`FindingState | None`

#### `list_finding_states(self, asset_id: str | None, lifecycle: FindingLifecycle | None, limit: int = 1000) -> list[FindingState]`

**Decorators:** @abstractmethod

List finding states with optional filters.

**Parameters:**

- `asset_id` (`str | None`)
- `lifecycle` (`FindingLifecycle | None`)
- `limit` (`int`) - default: `1000`

**Returns:**

`list[FindingState]`

## LocalStateBackend

**Inherits from:** StateBackend

SQLite-based local state storage.

### Methods

#### `__init__(self, db_path: str = ~/.stance/state.db)`

Initialize local state backend.

**Parameters:**

- `db_path` (`str`) - default: `~/.stance/state.db` - Path to SQLite database file

#### `save_scan(self, record: ScanRecord) -> None`

Save a scan record.

**Parameters:**

- `record` (`ScanRecord`)

**Returns:**

`None`

#### `get_scan(self, scan_id: str) -> ScanRecord | None`

Get a scan record by ID.

**Parameters:**

- `scan_id` (`str`)

**Returns:**

`ScanRecord | None`

#### `list_scans(self, limit: int = 100, status: ScanStatus | None, since: datetime | None) -> list[ScanRecord]`

List scan records with optional filters.

**Parameters:**

- `limit` (`int`) - default: `100`
- `status` (`ScanStatus | None`)
- `since` (`datetime | None`)

**Returns:**

`list[ScanRecord]`

#### `save_checkpoint(self, checkpoint: Checkpoint) -> None`

Save a checkpoint.

**Parameters:**

- `checkpoint` (`Checkpoint`)

**Returns:**

`None`

#### `get_checkpoint(self, collector_name: str, account_id: str, region: str) -> Checkpoint | None`

Get a checkpoint for a collector/account/region combination.

**Parameters:**

- `collector_name` (`str`)
- `account_id` (`str`)
- `region` (`str`)

**Returns:**

`Checkpoint | None`

#### `delete_checkpoint(self, collector_name: str, account_id: str, region: str) -> bool`

Delete a checkpoint.

**Parameters:**

- `collector_name` (`str`)
- `account_id` (`str`)
- `region` (`str`)

**Returns:**

`bool`

#### `save_finding_state(self, state: FindingState) -> None`

Save finding state.

**Parameters:**

- `state` (`FindingState`)

**Returns:**

`None`

#### `get_finding_state(self, finding_id: str) -> FindingState | None`

Get finding state by ID.

**Parameters:**

- `finding_id` (`str`)

**Returns:**

`FindingState | None`

#### `list_finding_states(self, asset_id: str | None, lifecycle: FindingLifecycle | None, limit: int = 1000) -> list[FindingState]`

List finding states with optional filters.

**Parameters:**

- `asset_id` (`str | None`)
- `lifecycle` (`FindingLifecycle | None`)
- `limit` (`int`) - default: `1000`

**Returns:**

`list[FindingState]`

## StateManager

High-level state management for Stance.

Provides convenient methods for tracking scan history,
managing checkpoints, and tracking finding lifecycle.

### Methods

#### `__init__(self, backend: StateBackend | None)`

Initialize state manager.

**Parameters:**

- `backend` (`StateBackend | None`) - State storage backend (default: LocalStateBackend)

#### `start_scan(self, scan_id: str, snapshot_id: str, config_name: str = default, account_id: str = , region: str = , collectors: list[str] | None) -> ScanRecord`

Record the start of a scan.

**Parameters:**

- `scan_id` (`str`) - Unique scan identifier
- `snapshot_id` (`str`) - Associated snapshot ID
- `config_name` (`str`) - default: `default` - Configuration name used
- `account_id` (`str`) - default: `` - Account being scanned
- `region` (`str`) - default: `` - Region being scanned
- `collectors` (`list[str] | None`) - List of collectors being run

**Returns:**

`ScanRecord` - ScanRecord for the started scan

#### `complete_scan(self, scan_id: str, asset_count: int, finding_count: int, error_message: str = ) -> ScanRecord | None`

Record the completion of a scan.

**Parameters:**

- `scan_id` (`str`) - Scan identifier
- `asset_count` (`int`) - Number of assets discovered
- `finding_count` (`int`) - Number of findings generated
- `error_message` (`str`) - default: `` - Error message if scan failed

**Returns:**

`ScanRecord | None` - Updated ScanRecord, or None if scan not found

#### `get_last_scan(self, account_id: str = , region: str = ) -> ScanRecord | None`

Get the last completed scan.

**Parameters:**

- `account_id` (`str`) - default: `` - Filter by account ID
- `region` (`str`) - default: `` - Filter by region

**Returns:**

`ScanRecord | None` - Last completed ScanRecord, or None

#### `update_checkpoint(self, collector_name: str, account_id: str, region: str, scan_id: str, cursor: str = ) -> Checkpoint`

Update checkpoint for incremental scanning.

**Parameters:**

- `collector_name` (`str`) - Name of the collector
- `account_id` (`str`) - Account ID
- `region` (`str`) - Region
- `scan_id` (`str`) - Current scan ID
- `cursor` (`str`) - default: `` - Optional continuation cursor

**Returns:**

`Checkpoint` - Updated Checkpoint

#### `get_checkpoint(self, collector_name: str, account_id: str, region: str) -> Checkpoint | None`

Get checkpoint for a collector/account/region.

**Parameters:**

- `collector_name` (`str`) - Name of the collector
- `account_id` (`str`) - Account ID
- `region` (`str`) - Region

**Returns:**

`Checkpoint | None` - Checkpoint if exists, None otherwise

#### `track_finding(self, finding_id: str, asset_id: str, rule_id: str) -> FindingState`

Track a finding's lifecycle.  Updates the finding state based on whether it's new or recurring.

**Parameters:**

- `finding_id` (`str`) - Finding identifier
- `asset_id` (`str`) - Associated asset ID
- `rule_id` (`str`) - Policy rule that generated the finding

**Returns:**

`FindingState` - Updated FindingState

#### `resolve_finding(self, finding_id: str) -> FindingState | None`

Mark a finding as resolved.

**Parameters:**

- `finding_id` (`str`) - Finding identifier

**Returns:**

`FindingState | None` - Updated FindingState, or None if not found

#### `suppress_finding(self, finding_id: str, suppressed_by: str, reason: str = ) -> FindingState | None`

Suppress a finding.

**Parameters:**

- `finding_id` (`str`) - Finding identifier
- `suppressed_by` (`str`) - User/system that suppressed the finding
- `reason` (`str`) - default: `` - Reason for suppression

**Returns:**

`FindingState | None` - Updated FindingState, or None if not found

#### `get_finding_stats(self) -> dict[(str, int)]`

Get finding statistics by lifecycle state.

**Returns:**

`dict[(str, int)]` - Dictionary mapping lifecycle states to counts

#### `cleanup_old_scans(self, days: int = 90) -> int`

Clean up old scan records.

**Parameters:**

- `days` (`int`) - default: `90` - Remove scans older than this many days

**Returns:**

`int` - Number of records cleaned up

### `get_state_manager(backend_type: str = local, **kwargs) -> StateManager`

Factory function to create a state manager.

**Parameters:**

- `backend_type` (`str`) - default: `local` - Type of backend (local, dynamodb, firestore, cosmosdb) **kwargs: Backend-specific configuration
- `**kwargs`

**Returns:**

`StateManager` - Configured StateManager
