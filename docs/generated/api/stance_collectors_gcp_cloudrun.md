# stance.collectors.gcp_cloudrun

GCP Cloud Run collector for Mantissa Stance.

Collects Cloud Run services and revisions with their security configurations
for security posture assessment.

## Contents

### Classes

- [GCPCloudRunCollector](#gcpcloudruncollector)

## GCPCloudRunCollector

**Inherits from:** BaseCollector

Collects GCP Cloud Run resources and configuration.

Gathers Cloud Run services and revisions with their security settings including:
- Ingress settings (all traffic, internal only, internal and Cloud Load Balancing)
- VPC access connector configuration
- Service account and IAM bindings
- Container configuration and environment variables (names only)
- Binary authorization configuration
- CPU and memory limits
- Scaling configuration (min/max instances)
- Traffic split across revisions

All API calls are read-only.

### Properties

#### `project_id(self) -> str`

Get the GCP project ID.

**Returns:**

`str`

### Methods

#### `__init__(self, project_id: str, credentials: Any | None, region: str | None, **kwargs: Any) -> None`

Initialize the GCP Cloud Run collector.

**Parameters:**

- `project_id` (`str`) - GCP project ID to collect from.
- `credentials` (`Any | None`) - Optional google-auth credentials object.
- `region` (`str | None`) - Optional specific region to collect from (default: all regions). **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

Collect all Cloud Run resources.

**Returns:**

`AssetCollection` - Collection of Cloud Run assets (services and revisions)
