# stance.dspm.access.gcp_audit

GCP Cloud Audit Logs Access Analyzer for DSPM.

Analyzes Cloud Audit Logs to detect stale GCS access patterns
and identify unused or over-privileged permissions.

## Contents

### Classes

- [GCPAuditLogAnalyzer](#gcpauditloganalyzer)

## Constants

### `GCS_ACTION_MAPPING`

Type: `dict`

Value: `{'storage.objects.get': 'read', 'storage.objects.list': 'list', 'storage.objects.create': 'write', 'storage.objects.update': 'write', 'storage.objects.delete': 'delete', 'storage.buckets.get': 'read', 'storage.buckets.getIamPolicy': 'read', 'storage.buckets.list': 'list', 'storage.buckets.update': 'write', 'storage.buckets.setIamPolicy': 'admin'}`

## GCPAuditLogAnalyzer

**Inherits from:** BaseAccessAnalyzer

GCP Cloud Audit Logs analyzer for GCS access patterns.

Queries Cloud Audit Logs to identify:
- Stale access (permissions not used in X days)
- Unused permissions (no access recorded)
- Over-privileged access (write permissions but only reads)

All operations are read-only.

### Methods

#### `__init__(self, config: AccessReviewConfig | None, project: str | None, credentials: Any | None)`

Initialize GCP Cloud Audit Log analyzer.

**Parameters:**

- `config` (`AccessReviewConfig | None`) - Optional access review configuration
- `project` (`str | None`) - GCP project ID
- `credentials` (`Any | None`) - Optional credentials object

#### `analyze_resource(self, resource_id: str) -> AccessReviewResult`

Analyze access patterns for a GCS bucket.

**Parameters:**

- `resource_id` (`str`) - GCS bucket name (with or without gs:// prefix)

**Returns:**

`AccessReviewResult` - Access review result with findings

#### `get_access_events(self, resource_id: str, start_time: datetime, end_time: datetime) -> Iterator[AccessEvent]`

Retrieve GCS access events from Cloud Audit Logs.

**Parameters:**

- `resource_id` (`str`) - GCS bucket name
- `start_time` (`datetime`) - Start of time range
- `end_time` (`datetime`) - End of time range

**Returns:**

`Iterator[AccessEvent]`

#### `get_resource_permissions(self, resource_id: str) -> dict[(str, dict[(str, Any)])]`

Get current permissions for a GCS bucket.  Analyzes bucket IAM policy to determine who has access.

**Parameters:**

- `resource_id` (`str`) - GCS bucket name

**Returns:**

`dict[(str, dict[(str, Any)])]` - Dictionary mapping principal_id to permission details

#### `get_bucket_location(self, bucket_name: str) -> str`

Get the location where a bucket is stored.

**Parameters:**

- `bucket_name` (`str`)

**Returns:**

`str`
