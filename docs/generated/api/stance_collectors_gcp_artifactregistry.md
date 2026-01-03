# stance.collectors.gcp_artifactregistry

GCP Artifact Registry collector for Mantissa Stance.

Collects Artifact Registry repositories, Docker images, and their
security configurations for posture assessment. Supports both
Artifact Registry (current) and legacy Container Registry.

## Contents

### Classes

- [GCPArtifactRegistryCollector](#gcpartifactregistrycollector)

## GCPArtifactRegistryCollector

**Inherits from:** BaseCollector

Collects GCP Artifact Registry repositories and Docker images.

Gathers repository configurations, IAM policies, Docker images,
and vulnerability scan results from Container Analysis API.
All API calls are read-only.

### Properties

#### `project_id(self) -> str`

Get the GCP project ID.

**Returns:**

`str`

### Methods

#### `__init__(self, project_id: str, credentials: Any | None, **kwargs: Any) -> None`

Initialize the GCP Artifact Registry collector.

**Parameters:**

- `project_id` (`str`) - GCP project ID to collect from.
- `credentials` (`Any | None`) - Optional google-auth credentials object. **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

Collect all Artifact Registry resources.

**Returns:**

`AssetCollection` - Collection of Artifact Registry assets

#### `collect_findings(self) -> FindingCollection`

Collect vulnerability findings from Container Analysis.

**Returns:**

`FindingCollection` - Collection of vulnerability findings from image scans
