# stance.collectors.gcp_storage

GCP Cloud Storage collector for Mantissa Stance.

Collects Cloud Storage bucket configurations including ACLs, IAM policies,
encryption settings, and public access status for security posture assessment.

## Contents

### Classes

- [GCPStorageCollector](#gcpstoragecollector)

## GCPStorageCollector

**Inherits from:** BaseCollector

Collects GCP Cloud Storage bucket resources and configuration.

Gathers bucket configurations, ACLs, IAM policies, encryption settings,
and public access status. All API calls are read-only.

### Properties

#### `project_id(self) -> str`

Get the GCP project ID.

**Returns:**

`str`

### Methods

#### `__init__(self, project_id: str, credentials: Any | None, **kwargs: Any) -> None`

Initialize the GCP Storage collector.

**Parameters:**

- `project_id` (`str`) - GCP project ID to collect from.
- `credentials` (`Any | None`) - Optional google-auth credentials object. **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

Collect all Cloud Storage buckets.

**Returns:**

`AssetCollection` - Collection of storage bucket assets
