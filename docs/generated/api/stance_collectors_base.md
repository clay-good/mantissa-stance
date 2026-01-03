# stance.collectors.base

Base collector framework for Mantissa Stance.

This module provides the abstract base class for all collectors,
along with the CollectorRunner for orchestrating multiple collectors.

## Contents

### Classes

- [CollectorResult](#collectorresult)
- [BaseCollector](#basecollector)
- [CollectorRunner](#collectorrunner)

## CollectorResult

**Tags:** dataclass

Result from running a collector.

Attributes:
    collector_name: Name of the collector that ran
    assets: Collection of assets discovered
    duration_seconds: How long the collection took
    errors: List of any errors encountered

### Attributes

| Name | Type | Default |
|------|------|---------|
| `collector_name` | `str` | - |
| `assets` | `AssetCollection` | - |
| `duration_seconds` | `float` | - |
| `errors` | `list[str]` | `field(...)` |

### Properties

#### `success(self) -> bool`

Check if collection completed without errors.

**Returns:**

`bool`

#### `asset_count(self) -> int`

Get number of assets collected.

**Returns:**

`int`

## BaseCollector

**Inherits from:** ABC

Abstract base class for cloud resource collectors.

All collectors must inherit from this class and implement
the collect() method. Collectors are responsible for gathering
configuration data from cloud services using read-only API calls.

Attributes:
    collector_name: Unique name for this collector
    resource_types: List of resource types this collector handles

### Attributes

| Name | Type | Default |
|------|------|---------|
| `collector_name` | `str` | `base` |
| `resource_types` | `list[str]` | `[]` |

### Properties

#### `account_id(self) -> str`

Get the AWS account ID.

**Returns:**

`str`

#### `region(self) -> str`

Get the AWS region.

**Returns:**

`str`

### Methods

#### `__init__(self, session: Any | None, region: str = us-east-1) -> None`

Initialize the collector.

**Parameters:**

- `session` (`Any | None`) - Optional boto3 Session. If None, uses default credentials.
- `region` (`str`) - default: `us-east-1` - AWS region to collect from (default: us-east-1)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

**Decorators:** @abstractmethod

Collect resources and return as AssetCollection.  Must be implemented by all collector subclasses.

**Returns:**

`AssetCollection` - Collection of discovered assets

## CollectorRunner

Runs multiple collectors and aggregates results.

Orchestrates the execution of collectors, handles errors,
and merges results into a single asset collection.

### Properties

#### `collectors(self) -> list[BaseCollector]`

Get the list of collectors.

**Returns:**

`list[BaseCollector]`

### Methods

#### `__init__(self, collectors: list[BaseCollector]) -> None`

Initialize the collector runner.

**Parameters:**

- `collectors` (`list[BaseCollector]`) - List of collector instances to run

**Returns:**

`None`

#### `run_collector(self, collector: BaseCollector) -> CollectorResult`

Run a single collector with timing and error handling.

**Parameters:**

- `collector` (`BaseCollector`) - Collector instance to run

**Returns:**

`CollectorResult` - CollectorResult with assets and metadata

#### `run_all(self) -> tuple[(AssetCollection, list[CollectorResult])]`

Run all collectors and merge results.

**Returns:**

`tuple[(AssetCollection, list[CollectorResult])]` - Tuple of (combined AssetCollection, list of CollectorResults)

#### `run_by_name(self, names: list[str]) -> tuple[(AssetCollection, list[CollectorResult])]`

Run only collectors matching the given names.

**Parameters:**

- `names` (`list[str]`) - List of collector names to run

**Returns:**

`tuple[(AssetCollection, list[CollectorResult])]` - Tuple of (combined AssetCollection, list of CollectorResults)
