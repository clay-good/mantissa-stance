# stance.dspm.cost.gcs_cost

GCS Cost Analyzer for DSPM.

Analyzes Google Cloud Storage bucket costs and identifies cold data
that can be archived or deleted to save costs.

## Contents

### Classes

- [GCSCostAnalyzer](#gcscostanalyzer)

## Constants

### `GCS_STORAGE_CLASS_MAP`

Type: `dict`

Value: `{'STANDARD': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'GCS_STANDARD\', ctx=Load())"', 'NEARLINE': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'GCS_NEARLINE\', ctx=Load())"', 'COLDLINE': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'GCS_COLDLINE\', ctx=Load())"', 'ARCHIVE': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'GCS_ARCHIVE\', ctx=Load())"', 'MULTI_REGIONAL': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'GCS_STANDARD\', ctx=Load())"', 'REGIONAL': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'GCS_STANDARD\', ctx=Load())"', 'DURABLE_REDUCED_AVAILABILITY': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'GCS_STANDARD\', ctx=Load())"'}`

## GCSCostAnalyzer

**Inherits from:** BaseCostAnalyzer

Google Cloud Storage cost analyzer.

Analyzes GCS buckets to identify cold data and estimate storage costs.
Uses GCS object metadata and optionally Cloud Monitoring for access patterns.

All operations are read-only.

### Methods

#### `__init__(self, config: CostAnalysisConfig | None, project: str | None, credentials: Any | None)`

Initialize GCS cost analyzer.

**Parameters:**

- `config` (`CostAnalysisConfig | None`) - Optional cost analysis configuration
- `project` (`str | None`) - GCP project ID
- `credentials` (`Any | None`) - Optional credentials object

#### `analyze_bucket(self, bucket_name: str) -> CostAnalysisResult`

Analyze a GCS bucket for cost optimization opportunities.

**Parameters:**

- `bucket_name` (`str`) - Name of the GCS bucket (with or without gs:// prefix)

**Returns:**

`CostAnalysisResult` - Cost analysis result with findings and metrics

#### `get_storage_metrics(self, bucket_name: str) -> StorageMetrics`

Get storage metrics for a GCS bucket.

**Parameters:**

- `bucket_name` (`str`) - Name of the GCS bucket

**Returns:**

`StorageMetrics` - Storage metrics including size, object count, costs

#### `get_object_access_info(self, bucket_name: str, object_key: str) -> ObjectAccessInfo | None`

Get access information for a specific GCS object.  Note: GCS doesn't provide last access time directly. We use time_created and updated timestamps as proxies.

**Parameters:**

- `bucket_name` (`str`) - Name of the GCS bucket
- `object_key` (`str`) - Object key/blob name

**Returns:**

`ObjectAccessInfo | None` - Object access information or None if not found

#### `list_objects_with_access_info(self, bucket_name: str, prefix: str = ) -> Iterator[ObjectAccessInfo]`

List objects with access information.

**Parameters:**

- `bucket_name` (`str`) - Name of the GCS bucket
- `prefix` (`str`) - default: `` - Optional prefix filter

**Returns:**

`Iterator[ObjectAccessInfo]`

#### `get_bucket_lifecycle_rules(self, bucket_name: str) -> list[dict[(str, Any)]]`

Get lifecycle rules for a bucket.

**Parameters:**

- `bucket_name` (`str`) - Name of the GCS bucket

**Returns:**

`list[dict[(str, Any)]]` - List of lifecycle rules

#### `get_bucket_location(self, bucket_name: str) -> str`

Get the location where a bucket is stored.

**Parameters:**

- `bucket_name` (`str`) - Name of the GCS bucket

**Returns:**

`str` - Location/region string

#### `list_buckets(self) -> Iterator[str]`

List all GCS buckets in the project.  Yields: Bucket names

**Returns:**

`Iterator[str]`
