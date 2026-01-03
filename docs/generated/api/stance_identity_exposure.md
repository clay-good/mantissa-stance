# stance.identity.exposure

Principal Data Exposure Analyzer for Identity Security.

Analyzes what sensitive data each principal can access by correlating
identity permissions with DSPM classification results.

## Contents

### Classes

- [ExposureSeverity](#exposureseverity)
- [ResourceClassification](#resourceclassification)
- [ExposedResource](#exposedresource)
- [ExposureFinding](#exposurefinding)
- [ExposureSummary](#exposuresummary)
- [ExposureResult](#exposureresult)
- [PrincipalExposureAnalyzer](#principalexposureanalyzer)

### Functions

- [create_classifications_from_scan_results](#create_classifications_from_scan_results)

## ExposureSeverity

**Inherits from:** Enum

Severity levels for exposure findings.

### Class Methods

#### `from_classification_and_permission(cls, classification: ClassificationLevel, permission: PermissionLevel) -> 'ExposureSeverity'`

**Decorators:** @classmethod

Calculate severity from classification and permission level.

**Parameters:**

- `classification` (`ClassificationLevel`)
- `permission` (`PermissionLevel`)

**Returns:**

`'ExposureSeverity'`

## ResourceClassification

**Tags:** dataclass

Classification information for a resource.

Attributes:
    resource_id: Resource identifier (bucket name, etc.)
    resource_type: Type of resource (s3_bucket, gcs_bucket, etc.)
    classification_level: Data classification level
    categories: Data categories found in the resource
    last_scanned: When the resource was last scanned
    finding_count: Number of DSPM findings in this resource
    metadata: Additional metadata from DSPM scan

### Attributes

| Name | Type | Default |
|------|------|---------|
| `resource_id` | `str` | - |
| `resource_type` | `str` | - |
| `classification_level` | `ClassificationLevel` | - |
| `categories` | `list[DataCategory]` | `field(...)` |
| `last_scanned` | `datetime | None` | - |
| `finding_count` | `int` | `0` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary representation.

**Returns:**

`dict[(str, Any)]`

## ExposedResource

**Tags:** dataclass

A resource that a principal has access to with classification info.

Attributes:
    resource_id: Resource identifier
    resource_type: Type of resource
    permission_level: Level of access the principal has
    permission_source: Where the permission comes from (policy, role, etc.)
    classification: Classification information for the resource
    risk_score: Calculated risk score based on classification and access
    policy_ids: Policies granting access

### Attributes

| Name | Type | Default |
|------|------|---------|
| `resource_id` | `str` | - |
| `resource_type` | `str` | - |
| `permission_level` | `PermissionLevel` | - |
| `permission_source` | `str` | - |
| `classification` | `ResourceClassification | None` | - |
| `risk_score` | `int` | `0` |
| `policy_ids` | `list[str]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary representation.

**Returns:**

`dict[(str, Any)]`

## ExposureFinding

**Tags:** dataclass

A finding about a principal's exposure to sensitive data.

Attributes:
    finding_id: Unique identifier
    finding_type: Type of finding
    severity: Severity level
    title: Short title
    description: Detailed description
    principal_id: Principal that has access
    principal_type: Type of principal
    resource_id: Resource with sensitive data
    resource_type: Type of resource
    permission_level: Access level the principal has
    classification_level: Data classification in the resource
    categories: Data categories accessible
    recommended_action: Suggested remediation
    metadata: Additional context
    detected_at: When the finding was created

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding_id` | `str` | - |
| `finding_type` | `FindingType` | - |
| `severity` | `ExposureSeverity` | - |
| `title` | `str` | - |
| `description` | `str` | - |
| `principal_id` | `str` | - |
| `principal_type` | `PrincipalType` | - |
| `resource_id` | `str` | - |
| `resource_type` | `str` | - |
| `permission_level` | `PermissionLevel` | - |
| `classification_level` | `ClassificationLevel` | - |
| `categories` | `list[DataCategory]` | `field(...)` |
| `recommended_action` | `str` | `` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |
| `detected_at` | `datetime` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary representation.

**Returns:**

`dict[(str, Any)]`

## ExposureSummary

**Tags:** dataclass

Summary of a principal's data exposure.

Attributes:
    principal: The principal being analyzed
    total_resources: Total number of resources accessible
    classified_resources: Number of resources with classification data
    sensitive_resources: Number of resources with CONFIDENTIAL+ data
    resources_by_classification: Count by classification level
    resources_by_category: Count by data category
    highest_classification: Highest classification level accessible
    highest_permission: Highest permission level held
    risk_score: Overall risk score for this principal

### Attributes

| Name | Type | Default |
|------|------|---------|
| `principal` | `Principal` | - |
| `total_resources` | `int` | `0` |
| `classified_resources` | `int` | `0` |
| `sensitive_resources` | `int` | `0` |
| `resources_by_classification` | `dict[(str, int)]` | `field(...)` |
| `resources_by_category` | `dict[(str, int)]` | `field(...)` |
| `highest_classification` | `ClassificationLevel | None` | - |
| `highest_permission` | `PermissionLevel` | `"Attribute(value=Name(id='PermissionLevel', ctx=Load()), attr='NONE', ctx=Load())"` |
| `risk_score` | `int` | `0` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary representation.

**Returns:**

`dict[(str, Any)]`

## ExposureResult

**Tags:** dataclass

Complete result of exposure analysis for a principal.

Attributes:
    analysis_id: Unique analysis identifier
    principal_id: Principal being analyzed
    summary: Summary of exposure
    exposed_resources: List of accessible resources with classifications
    findings: Security findings
    errors: Any errors during analysis
    started_at: When analysis started
    completed_at: When analysis completed

### Attributes

| Name | Type | Default |
|------|------|---------|
| `analysis_id` | `str` | - |
| `principal_id` | `str` | - |
| `summary` | `ExposureSummary | None` | - |
| `exposed_resources` | `list[ExposedResource]` | `field(...)` |
| `findings` | `list[ExposureFinding]` | `field(...)` |
| `errors` | `list[str]` | `field(...)` |
| `started_at` | `datetime` | `field(...)` |
| `completed_at` | `datetime | None` | - |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary representation.

**Returns:**

`dict[(str, Any)]`

## PrincipalExposureAnalyzer

Analyzes what sensitive data a principal can access.

Combines identity permissions from data access mappers with
DSPM classification results to determine exposure.

### Methods

#### `__init__(self, config: IdentityConfig | None, min_classification: ClassificationLevel = "Attribute(value=Name(id='ClassificationLevel', ctx=Load()), attr='INTERNAL', ctx=Load())")`

Initialize the exposure analyzer.

**Parameters:**

- `config` (`IdentityConfig | None`) - Optional identity configuration
- `min_classification` (`ClassificationLevel`) - default: `"Attribute(value=Name(id='ClassificationLevel', ctx=Load()), attr='INTERNAL', ctx=Load())"` - Minimum classification level to report

#### `register_classification(self, resource_id: str, classification: ResourceClassification) -> None`

Register a resource classification from DSPM scan results.

**Parameters:**

- `resource_id` (`str`) - Resource identifier
- `classification` (`ResourceClassification`) - Classification information

**Returns:**

`None`

#### `register_classifications(self, classifications: list[ResourceClassification]) -> None`

Register multiple resource classifications.

**Parameters:**

- `classifications` (`list[ResourceClassification]`) - List of classification information

**Returns:**

`None`

#### `clear_classifications(self) -> None`

Clear the classification cache.

**Returns:**

`None`

#### `get_classification(self, resource_id: str) -> ResourceClassification | None`

Get classification for a resource.

**Parameters:**

- `resource_id` (`str`) - Resource identifier

**Returns:**

`ResourceClassification | None` - Classification information or None

#### `analyze_principal_exposure(self, principal: Principal, resource_access_list: list[ResourceAccess]) -> ExposureResult`

Analyze what sensitive data a principal can access.

**Parameters:**

- `principal` (`Principal`) - The principal to analyze
- `resource_access_list` (`list[ResourceAccess]`) - List of resources the principal can access

**Returns:**

`ExposureResult` - Exposure analysis result

### `create_classifications_from_scan_results(scan_results: list[dict[(str, Any)]]) -> list[ResourceClassification]`

Create ResourceClassification objects from DSPM scan results.  This helper function converts DSPM ScanResult dictionaries into ResourceClassification objects for use with the exposure analyzer.

**Parameters:**

- `scan_results` (`list[dict[(str, Any)]]`) - List of DSPM scan result dictionaries

**Returns:**

`list[ResourceClassification]` - List of ResourceClassification objects
