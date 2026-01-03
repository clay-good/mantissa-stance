# stance.collectors.gcp_security

GCP Security Command Center collector for Mantissa Stance.

Collects security findings from Google Cloud Security Command Center (SCC)
for vulnerability and threat detection.

## Contents

### Classes

- [GCPSecurityCollector](#gcpsecuritycollector)

## GCPSecurityCollector

**Inherits from:** BaseCollector

Collects security findings from GCP Security Command Center.

Gathers vulnerability findings, misconfiguration detections,
and threat findings from SCC. All API calls are read-only.

### Properties

#### `project_id(self) -> str`

Get the GCP project ID.

**Returns:**

`str`

### Methods

#### `__init__(self, project_id: str, organization_id: str | None, credentials: Any | None, **kwargs: Any) -> None`

Initialize the GCP Security collector.

**Parameters:**

- `project_id` (`str`) - GCP project ID to collect from.
- `organization_id` (`str | None`) - Optional GCP organization ID for org-level findings.
- `credentials` (`Any | None`) - Optional google-auth credentials object. **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

Collect Security Command Center sources.  Note: The main findings collection is done via collect_findings().

**Returns:**

`AssetCollection` - Collection of SCC source assets (metadata)

#### `collect_findings(self) -> FindingCollection`

Collect security findings from SCC.

**Returns:**

`FindingCollection` - Collection of security findings
