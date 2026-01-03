# stance.drift.baseline

Baseline management for Mantissa Stance.

Provides baseline configuration storage, comparison,
and tracking for drift detection.

## Contents

### Classes

- [BaselineStatus](#baselinestatus)
- [BaselineConfig](#baselineconfig)
- [AssetBaseline](#assetbaseline)
- [Baseline](#baseline)
- [BaselineStorage](#baselinestorage)
- [InMemoryBaselineStorage](#inmemorybaselinestorage)
- [BaselineManager](#baselinemanager)

## BaselineStatus

**Inherits from:** Enum

Status of a baseline.

## BaselineConfig

**Tags:** dataclass

Configuration snapshot for baselining.

Attributes:
    config_hash: Hash of the configuration
    config_data: Full configuration data
    normalized_data: Normalized configuration for comparison

### Attributes

| Name | Type | Default |
|------|------|---------|
| `config_hash` | `str` | - |
| `config_data` | `dict[(str, Any)]` | - |
| `normalized_data` | `dict[(str, Any)]` | - |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary representation.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_asset(cls, asset: Asset) -> BaselineConfig`

**Decorators:** @classmethod

Create baseline config from an asset.

**Parameters:**

- `asset` (`Asset`)

**Returns:**

`BaselineConfig`

### Static Methods

#### `_normalize_config(config: dict) -> dict`

**Decorators:** @staticmethod

Normalize configuration for consistent comparison.  Removes volatile fields that change between scans but don't represent actual configuration changes.

**Parameters:**

- `config` (`dict`)

**Returns:**

`dict`

## AssetBaseline

**Tags:** dataclass

Baseline for a single asset.

Attributes:
    asset_id: Asset identifier
    asset_type: Resource type
    cloud_provider: Cloud provider
    region: Asset region
    baseline_config: Configuration baseline
    created_at: When baseline was created
    created_by: Who created the baseline
    tags: Baseline tags

### Attributes

| Name | Type | Default |
|------|------|---------|
| `asset_id` | `str` | - |
| `asset_type` | `str` | - |
| `cloud_provider` | `str` | - |
| `region` | `str` | - |
| `baseline_config` | `BaselineConfig` | - |
| `created_at` | `datetime` | `field(...)` |
| `created_by` | `str` | `system` |
| `tags` | `dict[(str, str)]` | `field(...)` |

### Methods

#### `matches(self, asset: Asset) -> bool`

Check if asset configuration matches baseline.

**Parameters:**

- `asset` (`Asset`)

**Returns:**

`bool`

#### `compare(self, asset: Asset) -> dict[(str, Any)]`

Compare asset configuration to baseline.

**Parameters:**

- `asset` (`Asset`)

**Returns:**

`dict[(str, Any)]`

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary representation.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict) -> AssetBaseline`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict`)

**Returns:**

`AssetBaseline`

## Baseline

**Tags:** dataclass

Collection of asset baselines.

Attributes:
    id: Baseline identifier
    name: Human-readable name
    description: Baseline description
    status: Baseline status
    asset_baselines: Individual asset baselines
    created_at: When baseline was created
    updated_at: When baseline was last updated
    created_by: Who created the baseline
    metadata: Additional metadata

### Attributes

| Name | Type | Default |
|------|------|---------|
| `id` | `str` | - |
| `name` | `str` | - |
| `description` | `str` | - |
| `status` | `BaselineStatus` | - |
| `asset_baselines` | `dict[(str, AssetBaseline)]` | `field(...)` |
| `created_at` | `datetime` | `field(...)` |
| `updated_at` | `datetime` | `field(...)` |
| `created_by` | `str` | `system` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

### Properties

#### `asset_count(self) -> int`

Return number of assets in baseline.

**Returns:**

`int`

### Methods

#### `add_asset_baseline(self, baseline: AssetBaseline) -> None`

Add an asset baseline.

**Parameters:**

- `baseline` (`AssetBaseline`)

**Returns:**

`None`

#### `remove_asset_baseline(self, asset_id: str) -> None`

Remove an asset baseline.

**Parameters:**

- `asset_id` (`str`)

**Returns:**

`None`

#### `get_asset_baseline(self, asset_id: str) -> AssetBaseline | None`

Get baseline for a specific asset.

**Parameters:**

- `asset_id` (`str`)

**Returns:**

`AssetBaseline | None`

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary representation.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict) -> Baseline`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict`)

**Returns:**

`Baseline`

## BaselineStorage

**Inherits from:** Protocol

Protocol for baseline storage backends.

### Methods

#### `save_baseline(self, baseline: Baseline) -> None`

Save a baseline.

**Parameters:**

- `baseline` (`Baseline`)

**Returns:**

`None`

#### `get_baseline(self, baseline_id: str) -> Baseline | None`

Get a baseline by ID.

**Parameters:**

- `baseline_id` (`str`)

**Returns:**

`Baseline | None`

#### `list_baselines(self) -> list[Baseline]`

List all baselines.

**Returns:**

`list[Baseline]`

#### `delete_baseline(self, baseline_id: str) -> None`

Delete a baseline.

**Parameters:**

- `baseline_id` (`str`)

**Returns:**

`None`

## InMemoryBaselineStorage

In-memory baseline storage for testing.

### Methods

#### `__init__(self)`

#### `save_baseline(self, baseline: Baseline) -> None`

Save a baseline.

**Parameters:**

- `baseline` (`Baseline`)

**Returns:**

`None`

#### `get_baseline(self, baseline_id: str) -> Baseline | None`

Get a baseline by ID.

**Parameters:**

- `baseline_id` (`str`)

**Returns:**

`Baseline | None`

#### `list_baselines(self) -> list[Baseline]`

List all baselines.

**Returns:**

`list[Baseline]`

#### `delete_baseline(self, baseline_id: str) -> None`

Delete a baseline.

**Parameters:**

- `baseline_id` (`str`)

**Returns:**

`None`

## BaselineManager

Manages configuration baselines.

Provides functionality to create, store, and compare
configuration baselines.

### Methods

#### `__init__(self, storage: BaselineStorage | None)`

Initialize baseline manager.

**Parameters:**

- `storage` (`BaselineStorage | None`) - Baseline storage backend

#### `create_baseline(self, name: str, assets: AssetCollection | list[Asset], description: str = , created_by: str = system, metadata: dict[(str, Any)] | None) -> Baseline`

Create a new baseline from assets.

**Parameters:**

- `name` (`str`) - Baseline name
- `assets` (`AssetCollection | list[Asset]`) - Assets to baseline
- `description` (`str`) - default: `` - Baseline description
- `created_by` (`str`) - default: `system` - Creator identifier
- `metadata` (`dict[(str, Any)] | None`) - Additional metadata

**Returns:**

`Baseline` - Created baseline

#### `get_baseline(self, baseline_id: str) -> Baseline | None`

Get a baseline by ID.

**Parameters:**

- `baseline_id` (`str`)

**Returns:**

`Baseline | None`

#### `get_active_baseline(self) -> Baseline | None`

Get the active baseline.

**Returns:**

`Baseline | None`

#### `list_baselines(self) -> list[Baseline]`

List all baselines.

**Returns:**

`list[Baseline]`

#### `compare_to_baseline(self, baseline_id: str, assets: AssetCollection | list[Asset]) -> dict[(str, Any)]`

Compare assets to a baseline.

**Parameters:**

- `baseline_id` (`str`) - Baseline to compare against
- `assets` (`AssetCollection | list[Asset]`) - Current assets

**Returns:**

`dict[(str, Any)]` - Comparison result with drift information

#### `update_baseline(self, baseline_id: str, assets: AssetCollection | list[Asset], asset_ids: list[str] | None) -> Baseline | None`

Update a baseline with new asset configurations.

**Parameters:**

- `baseline_id` (`str`) - Baseline to update
- `assets` (`AssetCollection | list[Asset]`) - New asset configurations
- `asset_ids` (`list[str] | None`) - Specific asset IDs to update (None = all)

**Returns:**

`Baseline | None` - Updated baseline or None if not found

#### `archive_baseline(self, baseline_id: str) -> bool`

Archive a baseline.

**Parameters:**

- `baseline_id` (`str`)

**Returns:**

`bool`

#### `delete_baseline(self, baseline_id: str) -> bool`

Delete a baseline.

**Parameters:**

- `baseline_id` (`str`)

**Returns:**

`bool`
