# stance.collectors.gcp_iam

GCP IAM collector for Mantissa Stance.

Collects IAM resources including service accounts, IAM policies and bindings,
and organization policies for security posture assessment.

## Contents

### Classes

- [GCPIAMCollector](#gcpiamcollector)

## GCPIAMCollector

**Inherits from:** BaseCollector

Collects GCP IAM resources and configuration.

Gathers service accounts, IAM policies, role bindings, and
organization policies. All API calls are read-only.

### Properties

#### `project_id(self) -> str`

Get the GCP project ID.

**Returns:**

`str`

### Methods

#### `__init__(self, project_id: str, credentials: Any | None, **kwargs: Any) -> None`

Initialize the GCP IAM collector.

**Parameters:**

- `project_id` (`str`) - GCP project ID to collect from.
- `credentials` (`Any | None`) - Optional google-auth credentials object. **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

Collect all IAM resources.

**Returns:**

`AssetCollection` - Collection of IAM assets
