# stance.dspm.access.cloudtrail

AWS CloudTrail Access Analyzer for DSPM.

Analyzes CloudTrail logs to detect stale S3 access patterns
and identify unused or over-privileged permissions.

## Contents

### Classes

- [CloudTrailAccessAnalyzer](#cloudtrailaccessanalyzer)

## Constants

### `S3_ACTION_MAPPING`

Type: `dict`

Value: `{'GetObject': 'read', 'HeadObject': 'read', 'GetObjectAcl': 'read', 'GetObjectTagging': 'read', 'GetObjectAttributes': 'read', 'PutObject': 'write', 'PutObjectAcl': 'write', 'PutObjectTagging': 'write', 'CopyObject': 'write', 'UploadPart': 'write', 'CompleteMultipartUpload': 'write', 'DeleteObject': 'delete', 'DeleteObjects': 'delete', 'DeleteObjectTagging': 'delete', 'ListBucket': 'list', 'ListBucketVersions': 'list', 'ListMultipartUploadParts': 'list'}`

## CloudTrailAccessAnalyzer

**Inherits from:** BaseAccessAnalyzer

AWS CloudTrail analyzer for S3 access patterns.

Queries CloudTrail data events to identify:
- Stale access (permissions not used in X days)
- Unused permissions (no access recorded)
- Over-privileged access (write permissions but only reads)

All operations are read-only.

### Methods

#### `__init__(self, config: AccessReviewConfig | None, session: Any | None, region: str = us-east-1, trail_name: str | None, use_lake: bool = False, lake_query_results_bucket: str | None)`

Initialize CloudTrail access analyzer.

**Parameters:**

- `config` (`AccessReviewConfig | None`) - Optional access review configuration
- `session` (`Any | None`) - Optional boto3 Session
- `region` (`str`) - default: `us-east-1` - AWS region
- `trail_name` (`str | None`) - CloudTrail trail name (for lookup events)
- `use_lake` (`bool`) - default: `False` - Whether to use CloudTrail Lake for queries
- `lake_query_results_bucket` (`str | None`) - S3 bucket for Lake query results

#### `analyze_resource(self, resource_id: str) -> AccessReviewResult`

Analyze access patterns for an S3 bucket.

**Parameters:**

- `resource_id` (`str`) - S3 bucket name

**Returns:**

`AccessReviewResult` - Access review result with findings

#### `get_access_events(self, resource_id: str, start_time: datetime, end_time: datetime) -> Iterator[AccessEvent]`

Retrieve S3 access events from CloudTrail.

**Parameters:**

- `resource_id` (`str`) - S3 bucket name
- `start_time` (`datetime`) - Start of time range
- `end_time` (`datetime`) - End of time range

**Returns:**

`Iterator[AccessEvent]`

#### `get_resource_permissions(self, resource_id: str) -> dict[(str, dict[(str, Any)])]`

Get current permissions for an S3 bucket.  Analyzes bucket policy and ACL to determine who has access.

**Parameters:**

- `resource_id` (`str`) - S3 bucket name

**Returns:**

`dict[(str, dict[(str, Any)])]` - Dictionary mapping principal_id to permission details

#### `get_bucket_location(self, bucket_name: str) -> str`

Get the region where a bucket is located.

**Parameters:**

- `bucket_name` (`str`)

**Returns:**

`str`
