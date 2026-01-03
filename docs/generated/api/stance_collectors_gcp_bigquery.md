# stance.collectors.gcp_bigquery

GCP BigQuery collector for Mantissa Stance.

Collects BigQuery datasets, tables, and their security configurations
for security posture assessment.

## Contents

### Classes

- [GCPBigQueryCollector](#gcpbigquerycollector)

## GCPBigQueryCollector

**Inherits from:** BaseCollector

Collects GCP BigQuery resources and configuration.

Gathers BigQuery datasets and tables with their security settings including:
- Access control lists (dataset and table level)
- Encryption configuration (CMEK vs Google-managed)
- Default table expiration settings
- Labels and metadata
- Public dataset detection

All API calls are read-only.

### Properties

#### `project_id(self) -> str`

Get the GCP project ID.

**Returns:**

`str`

### Methods

#### `__init__(self, project_id: str, credentials: Any | None, **kwargs: Any) -> None`

Initialize the GCP BigQuery collector.

**Parameters:**

- `project_id` (`str`) - GCP project ID to collect from.
- `credentials` (`Any | None`) - Optional google-auth credentials object. **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

Collect all BigQuery resources.

**Returns:**

`AssetCollection` - Collection of BigQuery assets
