# stance.collectors.gcp_functions

GCP Cloud Functions collector for Mantissa Stance.

Collects Cloud Functions (1st and 2nd gen) and their security configurations
for security posture assessment.

## Contents

### Classes

- [GCPCloudFunctionsCollector](#gcpcloudfunctionscollector)

## Constants

### `DEPRECATED_RUNTIMES`

Type: `str`

Value: `"Set(elts=[Constant(value='python37'), Constant(value='python38'), Constant(value='nodejs10'), Constant(value='nodejs12'), Constant(value='nodejs14'), Constant(value='go111'), Constant(value='go113'), Constant(value='dotnetcore3'), Constant(value='ruby26'), Constant(value='ruby27')])"`

### `EOL_APPROACHING_RUNTIMES`

Type: `str`

Value: `"Set(elts=[Constant(value='nodejs16'), Constant(value='python39'), Constant(value='go116'), Constant(value='java11'), Constant(value='ruby30')])"`

## GCPCloudFunctionsCollector

**Inherits from:** BaseCollector

Collects GCP Cloud Functions resources and configuration.

Gathers Cloud Functions with their security settings including:
- Ingress settings (all traffic, internal only, internal and GCLB)
- VPC connector configuration
- Service account and IAM bindings
- Environment variables (names only)
- Runtime and deprecated runtime detection
- HTTPS trigger configuration
- Secret references

Supports both Cloud Functions 1st gen and 2nd gen.
All API calls are read-only.

### Properties

#### `project_id(self) -> str`

Get the GCP project ID.

**Returns:**

`str`

### Methods

#### `__init__(self, project_id: str, credentials: Any | None, region: str | None, **kwargs: Any) -> None`

Initialize the GCP Cloud Functions collector.

**Parameters:**

- `project_id` (`str`) - GCP project ID to collect from.
- `credentials` (`Any | None`) - Optional google-auth credentials object.
- `region` (`str | None`) - Optional specific region to collect from (default: all regions). **kwargs: Additional configuration.
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `collect(self) -> AssetCollection`

Collect all Cloud Functions resources.

**Returns:**

`AssetCollection` - Collection of Cloud Functions assets
