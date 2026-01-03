# stance.collectors.gcp_sql

GCP Cloud SQL collector for Mantissa Stance.

Collects Cloud SQL instances, databases, and their security configurations
for security posture assessment.

## Contents

### Classes

- [GCPCloudSQLCollector](#gcpcloudsqlcollector)

## GCPCloudSQLCollector

**Inherits from:** BaseCollector

Collects GCP Cloud SQL resources and configuration.

Gathers Cloud SQL instances with their security settings including:
- Encryption configuration (CMEK vs Google-managed)
- Public IP and authorized networks
- SSL/TLS requirements
- Backup configuration
- Database flags for security settings

All API calls are read-only.

### Properties

#### `project_id(self) -> str`

Get the GCP project ID.

**Returns:**

`str`

### Methods

#### `__init__(self, project_id: str, credentials: Any | None, **kwargs: Any) -> None`

Initialize the GCP Cloud SQL collector.

**Parameters:**

- `project_id` (`str`) - GCP project ID to collect from.
- `credentials` (`Any | None`) - Optional google-auth credentials object. **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

Collect all Cloud SQL resources.

**Returns:**

`AssetCollection` - Collection of Cloud SQL assets
