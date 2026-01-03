# stance.dspm.cost.s3_cost

AWS S3 Cost Analyzer for DSPM.

Analyzes S3 bucket storage costs and identifies cold data
that can be archived or deleted to save costs.

## Contents

### Classes

- [S3CostAnalyzer](#s3costanalyzer)

## Constants

### `S3_STORAGE_CLASS_MAP`

Type: `dict`

Value: `{'STANDARD': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'S3_STANDARD\', ctx=Load())"', 'INTELLIGENT_TIERING': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'S3_INTELLIGENT_TIERING\', ctx=Load())"', 'STANDARD_IA': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'S3_STANDARD_IA\', ctx=Load())"', 'ONEZONE_IA': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'S3_ONE_ZONE_IA\', ctx=Load())"', 'GLACIER': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'S3_GLACIER_FLEXIBLE\', ctx=Load())"', 'GLACIER_IR': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'S3_GLACIER_INSTANT\', ctx=Load())"', 'DEEP_ARCHIVE': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'S3_GLACIER_DEEP_ARCHIVE\', ctx=Load())"', 'REDUCED_REDUNDANCY': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'S3_STANDARD\', ctx=Load())"', 'OUTPOSTS': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'S3_STANDARD\', ctx=Load())"', 'EXPRESS_ONEZONE': '"Attribute(value=Name(id=\'StorageTier\', ctx=Load()), attr=\'S3_STANDARD\', ctx=Load())"'}`

## S3CostAnalyzer

**Inherits from:** BaseCostAnalyzer

AWS S3 storage cost analyzer.

Analyzes S3 buckets to identify cold data and estimate storage costs.
Uses S3 object metadata and optionally S3 Storage Lens or CloudWatch
for access patterns.

All operations are read-only.

### Methods

#### `__init__(self, config: CostAnalysisConfig | None, session: Any | None, region: str = us-east-1)`

Initialize S3 cost analyzer.

**Parameters:**

- `config` (`CostAnalysisConfig | None`) - Optional cost analysis configuration
- `session` (`Any | None`) - Optional boto3 Session
- `region` (`str`) - default: `us-east-1` - AWS region

#### `analyze_bucket(self, bucket_name: str) -> CostAnalysisResult`

Analyze an S3 bucket for cost optimization opportunities.

**Parameters:**

- `bucket_name` (`str`) - Name of the S3 bucket

**Returns:**

`CostAnalysisResult` - Cost analysis result with findings and metrics

#### `get_storage_metrics(self, bucket_name: str) -> StorageMetrics`

Get storage metrics for an S3 bucket.

**Parameters:**

- `bucket_name` (`str`) - Name of the S3 bucket

**Returns:**

`StorageMetrics` - Storage metrics including size, object count, costs

#### `get_object_access_info(self, bucket_name: str, object_key: str) -> ObjectAccessInfo | None`

Get access information for a specific S3 object.  Note: S3 doesn't provide last access time directly. We use last modified time as a proxy and optionally query CloudWatch for request metrics.

**Parameters:**

- `bucket_name` (`str`) - Name of the S3 bucket
- `object_key` (`str`) - Object key

**Returns:**

`ObjectAccessInfo | None` - Object access information or None if not found

#### `list_objects_with_access_info(self, bucket_name: str, prefix: str = ) -> Iterator[ObjectAccessInfo]`

List objects with access information.

**Parameters:**

- `bucket_name` (`str`) - Name of the S3 bucket
- `prefix` (`str`) - default: `` - Optional prefix filter

**Returns:**

`Iterator[ObjectAccessInfo]`

#### `get_bucket_lifecycle_rules(self, bucket_name: str) -> list[dict[(str, Any)]]`

Get lifecycle rules for a bucket.

**Parameters:**

- `bucket_name` (`str`) - Name of the S3 bucket

**Returns:**

`list[dict[(str, Any)]]` - List of lifecycle rules

#### `get_intelligent_tiering_config(self, bucket_name: str) -> dict[(str, Any)] | None`

Get Intelligent-Tiering configuration for a bucket.

**Parameters:**

- `bucket_name` (`str`) - Name of the S3 bucket

**Returns:**

`dict[(str, Any)] | None` - Intelligent-Tiering configuration or None

#### `list_buckets(self) -> Iterator[str]`

List all S3 buckets in the account.  Yields: Bucket names

**Returns:**

`Iterator[str]`
