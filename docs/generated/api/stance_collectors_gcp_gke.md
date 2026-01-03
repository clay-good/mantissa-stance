# stance.collectors.gcp_gke

GCP Google Kubernetes Engine (GKE) collector for Mantissa Stance.

Collects GKE clusters, node pools, and their security configurations
for posture assessment.

## Contents

### Classes

- [GKECollector](#gkecollector)

## GKECollector

**Inherits from:** BaseCollector

Collects GCP GKE clusters, node pools, and security configurations.

Gathers GKE cluster configurations including networking, security,
Workload Identity, Binary Authorization, and node pool settings.
All API calls are read-only.

### Properties

#### `project_id(self) -> str`

Get the GCP project ID.

**Returns:**

`str`

### Methods

#### `__init__(self, project_id: str, credentials: Any | None, location: str | None, **kwargs: Any) -> None`

Initialize the GCP GKE collector.

**Parameters:**

- `project_id` (`str`) - GCP project ID to collect from.
- `credentials` (`Any | None`) - Optional google-auth credentials object.
- `location` (`str | None`) - Optional specific location (region or zone) to collect from.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

Collect all GKE resources.

**Returns:**

`AssetCollection` - Collection of GKE assets
