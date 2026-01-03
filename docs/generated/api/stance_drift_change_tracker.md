# stance.drift.change_tracker

Change tracking for Mantissa Stance.

Provides asset change tracking over time, change timeline,
and change attribution.

## Contents

### Classes

- [ChangeType](#changetype)
- [ConfigSnapshot](#configsnapshot)
- [ChangeEvent](#changeevent)
- [AssetHistory](#assethistory)
- [ChangeStorage](#changestorage)
- [InMemoryChangeStorage](#inmemorychangestorage)
- [ChangeTracker](#changetracker)

## ChangeType

**Inherits from:** Enum

Types of asset changes.

## ConfigSnapshot

**Tags:** dataclass

Point-in-time configuration snapshot.

Attributes:
    snapshot_id: Unique snapshot identifier
    config_hash: Hash of configuration
    config_data: Full configuration data
    captured_at: When snapshot was taken

### Attributes

| Name | Type | Default |
|------|------|---------|
| `snapshot_id` | `str` | - |
| `config_hash` | `str` | - |
| `config_data` | `dict[(str, Any)]` | - |
| `captured_at` | `datetime` | - |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_asset(cls, asset: Asset, snapshot_id: str) -> ConfigSnapshot`

**Decorators:** @classmethod

Create snapshot from asset.

**Parameters:**

- `asset` (`Asset`)
- `snapshot_id` (`str`)

**Returns:**

`ConfigSnapshot`

## ChangeEvent

**Tags:** dataclass

Record of a single change event.

Attributes:
    event_id: Unique event identifier
    asset_id: Asset that changed
    change_type: Type of change
    occurred_at: When change occurred
    detected_at: When change was detected
    previous_snapshot: Previous configuration (if applicable)
    current_snapshot: Current configuration (if applicable)
    changed_paths: List of changed configuration paths
    attributed_to: Who/what made the change
    source: Source of change (api, console, terraform, etc.)
    metadata: Additional metadata

### Attributes

| Name | Type | Default |
|------|------|---------|
| `event_id` | `str` | - |
| `asset_id` | `str` | - |
| `change_type` | `ChangeType` | - |
| `occurred_at` | `datetime` | - |
| `detected_at` | `datetime` | - |
| `previous_snapshot` | `ConfigSnapshot | None` | - |
| `current_snapshot` | `ConfigSnapshot | None` | - |
| `changed_paths` | `list[str]` | `field(...)` |
| `attributed_to` | `str` | `unknown` |
| `source` | `str` | `unknown` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## AssetHistory

**Tags:** dataclass

Change history for a single asset.

Attributes:
    asset_id: Asset identifier
    asset_type: Resource type
    cloud_provider: Cloud provider
    events: List of change events
    first_seen: When asset was first observed
    last_seen: When asset was last observed
    current_config_hash: Current configuration hash

### Attributes

| Name | Type | Default |
|------|------|---------|
| `asset_id` | `str` | - |
| `asset_type` | `str` | - |
| `cloud_provider` | `str` | - |
| `events` | `list[ChangeEvent]` | `field(...)` |
| `first_seen` | `datetime | None` | - |
| `last_seen` | `datetime | None` | - |
| `current_config_hash` | `str` | `` |

### Methods

#### `add_event(self, event: ChangeEvent) -> None`

Add a change event.

**Parameters:**

- `event` (`ChangeEvent`)

**Returns:**

`None`

#### `get_recent_events(self, limit: int = 10) -> list[ChangeEvent]`

Get most recent events.

**Parameters:**

- `limit` (`int`) - default: `10`

**Returns:**

`list[ChangeEvent]`

#### `get_events_in_range(self, start: datetime, end: datetime) -> list[ChangeEvent]`

Get events within time range.

**Parameters:**

- `start` (`datetime`)
- `end` (`datetime`)

**Returns:**

`list[ChangeEvent]`

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## ChangeStorage

**Inherits from:** Protocol

Protocol for change storage backends.

### Methods

#### `save_event(self, event: ChangeEvent) -> None`

Save a change event.

**Parameters:**

- `event` (`ChangeEvent`)

**Returns:**

`None`

#### `get_asset_history(self, asset_id: str) -> AssetHistory | None`

Get history for an asset.

**Parameters:**

- `asset_id` (`str`)

**Returns:**

`AssetHistory | None`

#### `get_recent_events(self, limit: int) -> list[ChangeEvent]`

Get recent events across all assets.

**Parameters:**

- `limit` (`int`)

**Returns:**

`list[ChangeEvent]`

#### `save_snapshot(self, asset_id: str, snapshot: ConfigSnapshot) -> None`

Save a configuration snapshot.

**Parameters:**

- `asset_id` (`str`)
- `snapshot` (`ConfigSnapshot`)

**Returns:**

`None`

#### `get_latest_snapshot(self, asset_id: str) -> ConfigSnapshot | None`

Get latest snapshot for an asset.

**Parameters:**

- `asset_id` (`str`)

**Returns:**

`ConfigSnapshot | None`

## InMemoryChangeStorage

In-memory change storage for testing.

### Methods

#### `__init__(self)`

#### `save_event(self, event: ChangeEvent) -> None`

Save a change event.

**Parameters:**

- `event` (`ChangeEvent`)

**Returns:**

`None`

#### `get_asset_history(self, asset_id: str) -> AssetHistory | None`

Get history for an asset.

**Parameters:**

- `asset_id` (`str`)

**Returns:**

`AssetHistory | None`

#### `get_recent_events(self, limit: int = 100) -> list[ChangeEvent]`

Get recent events.

**Parameters:**

- `limit` (`int`) - default: `100`

**Returns:**

`list[ChangeEvent]`

#### `save_snapshot(self, asset_id: str, snapshot: ConfigSnapshot) -> None`

Save a configuration snapshot.

**Parameters:**

- `asset_id` (`str`)
- `snapshot` (`ConfigSnapshot`)

**Returns:**

`None`

#### `get_latest_snapshot(self, asset_id: str) -> ConfigSnapshot | None`

Get latest snapshot for an asset.

**Parameters:**

- `asset_id` (`str`)

**Returns:**

`ConfigSnapshot | None`

## ChangeTracker

Tracks asset changes over time.

Monitors configuration changes, maintains history,
and provides change attribution when possible.

### Methods

#### `__init__(self, storage: ChangeStorage | None)`

Initialize change tracker.

**Parameters:**

- `storage` (`ChangeStorage | None`) - Change storage backend

#### `track_changes(self, assets: AssetCollection | list[Asset], snapshot_id: str | None) -> list[ChangeEvent]`

Track changes in assets compared to previous snapshots.

**Parameters:**

- `assets` (`AssetCollection | list[Asset]`) - Current assets
- `snapshot_id` (`str | None`) - Optional snapshot identifier

**Returns:**

`list[ChangeEvent]` - List of detected change events

#### `record_deletion(self, asset_id: str, asset_type: str = unknown, cloud_provider: str = unknown) -> ChangeEvent`

Record an asset deletion.

**Parameters:**

- `asset_id` (`str`) - Deleted asset ID
- `asset_type` (`str`) - default: `unknown` - Resource type
- `cloud_provider` (`str`) - default: `unknown` - Cloud provider

**Returns:**

`ChangeEvent` - Deletion event

#### `get_asset_history(self, asset_id: str) -> AssetHistory | None`

Get change history for an asset.

**Parameters:**

- `asset_id` (`str`)

**Returns:**

`AssetHistory | None`

#### `get_recent_changes(self, limit: int = 100, asset_type: str | None, change_type: ChangeType | None) -> list[ChangeEvent]`

Get recent changes with optional filters.

**Parameters:**

- `limit` (`int`) - default: `100` - Maximum number of events
- `asset_type` (`str | None`) - Filter by asset type
- `change_type` (`ChangeType | None`) - Filter by change type

**Returns:**

`list[ChangeEvent]` - List of change events

#### `get_changes_in_range(self, start: datetime, end: datetime, asset_ids: list[str] | None) -> list[ChangeEvent]`

Get changes within a time range.

**Parameters:**

- `start` (`datetime`) - Start of range
- `end` (`datetime`) - End of range
- `asset_ids` (`list[str] | None`) - Optional filter by asset IDs

**Returns:**

`list[ChangeEvent]` - List of change events

#### `get_change_timeline(self, asset_id: str, days: int = 30) -> list[dict[(str, Any)]]`

Get change timeline for an asset.

**Parameters:**

- `asset_id` (`str`) - Asset to get timeline for
- `days` (`int`) - default: `30` - Number of days to include

**Returns:**

`list[dict[(str, Any)]]` - Timeline entries

#### `get_change_summary(self, hours: int = 24) -> dict[(str, Any)]`

Get summary of recent changes.

**Parameters:**

- `hours` (`int`) - default: `24` - Number of hours to summarize

**Returns:**

`dict[(str, Any)]` - Summary dictionary
