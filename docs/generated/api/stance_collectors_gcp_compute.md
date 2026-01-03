# stance.collectors.gcp_compute

GCP Compute Engine collector for Mantissa Stance.

Collects Compute Engine instances, firewall rules, VPC networks,
and related network configuration for security posture assessment.

## Contents

### Classes

- [GCPComputeCollector](#gcpcomputecollector)

## GCPComputeCollector

**Inherits from:** BaseCollector

Collects GCP Compute Engine resources and configuration.

Gathers VM instances, firewall rules, VPC networks, and subnetworks.
All API calls are read-only.

### Properties

#### `project_id(self) -> str`

Get the GCP project ID.

**Returns:**

`str`

### Methods

#### `__init__(self, project_id: str, credentials: Any | None, zone: str | None, **kwargs: Any) -> None`

Initialize the GCP Compute collector.

**Parameters:**

- `project_id` (`str`) - GCP project ID to collect from.
- `credentials` (`Any | None`) - Optional google-auth credentials object.
- `zone` (`str | None`) - Optional specific zone to collect from (default: all zones). **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

Collect all Compute Engine resources.

**Returns:**

`AssetCollection` - Collection of compute assets
