# stance.exposure.base

Base classes for Exposure Management.

Provides data models and abstract base class for discovering and analyzing
publicly accessible cloud resources and correlating with data sensitivity.

## Contents

### Classes

- [ExposureType](#exposuretype)
- [ExposureSeverity](#exposureseverity)
- [ExposureFindingType](#exposurefindingtype)
- [ExposureConfig](#exposureconfig)
- [PublicAsset](#publicasset)
- [ExposureFinding](#exposurefinding)
- [ExposureInventorySummary](#exposureinventorysummary)
- [ExposureInventoryResult](#exposureinventoryresult)
- [BaseExposureAnalyzer](#baseexposureanalyzer)

## ExposureType

**Inherits from:** Enum

Types of public exposure.

## ExposureSeverity

**Inherits from:** Enum

Severity levels for exposure findings.

### Properties

#### `rank(self) -> int`

Numeric rank for comparison (higher = more severe).

**Returns:**

`int`

## ExposureFindingType

**Inherits from:** Enum

Types of exposure-related findings.

## ExposureConfig

**Tags:** dataclass

Configuration for exposure analysis.

Attributes:
    include_storage: Whether to include storage resources
    include_compute: Whether to include compute resources
    include_database: Whether to include database resources
    include_network: Whether to include network resources
    include_kubernetes: Whether to include Kubernetes resources
    cloud_providers: List of cloud providers to analyze
    regions: List of regions to analyze (empty = all)
    min_sensitivity_for_critical: Minimum classification for critical severity

### Attributes

| Name | Type | Default |
|------|------|---------|
| `include_storage` | `bool` | `True` |
| `include_compute` | `bool` | `True` |
| `include_database` | `bool` | `True` |
| `include_network` | `bool` | `True` |
| `include_kubernetes` | `bool` | `True` |
| `cloud_providers` | `list[str]` | `field(...)` |
| `regions` | `list[str]` | `field(...)` |
| `min_sensitivity_for_critical` | `str` | `confidential` |

## PublicAsset

**Tags:** dataclass

A publicly accessible cloud resource.

Attributes:
    asset_id: Unique identifier (ARN, resource ID, etc.)
    name: Human-readable name
    exposure_type: Type of exposure
    cloud_provider: Cloud provider (aws, gcp, azure)
    account_id: Account/project ID
    region: Region where resource is located
    resource_type: Type of resource (e.g., aws_s3_bucket)
    public_endpoint: Public URL or IP if applicable
    public_ips: List of public IP addresses
    access_method: How public access is granted (acl, policy, network, etc.)
    detected_at: When the public exposure was detected
    data_classification: Data sensitivity if known (from DSPM)
    data_categories: Data categories found (PII, PCI, etc.)
    has_sensitive_data: Whether sensitive data is present
    risk_score: Numeric risk score (0-100)
    metadata: Additional metadata

### Attributes

| Name | Type | Default |
|------|------|---------|
| `asset_id` | `str` | - |
| `name` | `str` | - |
| `exposure_type` | `ExposureType` | - |
| `cloud_provider` | `str` | - |
| `account_id` | `str` | - |
| `region` | `str` | - |
| `resource_type` | `str` | - |
| `public_endpoint` | `str | None` | - |
| `public_ips` | `list[str]` | `field(...)` |
| `access_method` | `str` | `unknown` |
| `detected_at` | `datetime` | `field(...)` |
| `data_classification` | `str | None` | - |
| `data_categories` | `list[str]` | `field(...)` |
| `has_sensitive_data` | `bool` | `False` |
| `risk_score` | `float` | `0.0` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## ExposureFinding

**Tags:** dataclass

A finding about a publicly exposed resource.

Attributes:
    finding_id: Unique identifier
    finding_type: Type of finding
    severity: Severity level
    title: Short title
    description: Detailed description
    asset_id: Affected asset ID
    asset_name: Human-readable asset name
    exposure_type: Type of exposure
    cloud_provider: Cloud provider
    region: Region
    data_classification: Data sensitivity if known
    data_categories: Data categories affected
    recommended_action: Suggested remediation
    risk_score: Numeric risk score (0-100)
    metadata: Additional context
    detected_at: When finding was generated

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding_id` | `str` | - |
| `finding_type` | `ExposureFindingType` | - |
| `severity` | `ExposureSeverity` | - |
| `title` | `str` | - |
| `description` | `str` | - |
| `asset_id` | `str` | - |
| `asset_name` | `str` | - |
| `exposure_type` | `ExposureType` | - |
| `cloud_provider` | `str` | - |
| `region` | `str` | - |
| `data_classification` | `str | None` | - |
| `data_categories` | `list[str]` | `field(...)` |
| `recommended_action` | `str` | `` |
| `risk_score` | `float` | `0.0` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |
| `detected_at` | `datetime` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## ExposureInventorySummary

**Tags:** dataclass

Summary statistics for exposure inventory.

Attributes:
    total_public_assets: Total number of public assets
    assets_by_type: Count by exposure type
    assets_by_cloud: Count by cloud provider
    assets_by_region: Count by region
    assets_with_sensitive_data: Count with sensitive data
    critical_exposures: Count of critical exposure findings
    high_exposures: Count of high exposure findings
    average_risk_score: Average risk score across assets

### Attributes

| Name | Type | Default |
|------|------|---------|
| `total_public_assets` | `int` | `0` |
| `assets_by_type` | `dict[(str, int)]` | `field(...)` |
| `assets_by_cloud` | `dict[(str, int)]` | `field(...)` |
| `assets_by_region` | `dict[(str, int)]` | `field(...)` |
| `assets_with_sensitive_data` | `int` | `0` |
| `critical_exposures` | `int` | `0` |
| `high_exposures` | `int` | `0` |
| `average_risk_score` | `float` | `0.0` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## ExposureInventoryResult

**Tags:** dataclass

Result of exposure inventory analysis.

Attributes:
    inventory_id: Unique identifier
    config: Configuration used
    started_at: Analysis start time
    completed_at: Analysis completion time
    public_assets: List of public assets found
    findings: List of exposure findings
    summary: Summary statistics
    errors: Errors encountered

### Attributes

| Name | Type | Default |
|------|------|---------|
| `inventory_id` | `str` | - |
| `config` | `ExposureConfig` | - |
| `started_at` | `datetime` | - |
| `completed_at` | `datetime | None` | - |
| `public_assets` | `list[PublicAsset]` | `field(...)` |
| `findings` | `list[ExposureFinding]` | `field(...)` |
| `summary` | `ExposureInventorySummary` | `field(...)` |
| `errors` | `list[str]` | `field(...)` |

### Properties

#### `has_findings(self) -> bool`

Check if inventory has any findings.

**Returns:**

`bool`

#### `findings_by_type(self) -> dict[(str, int)]`

Get count of findings by type.

**Returns:**

`dict[(str, int)]`

#### `findings_by_severity(self) -> dict[(str, int)]`

Get count of findings by severity.

**Returns:**

`dict[(str, int)]`

#### `critical_findings(self) -> list[ExposureFinding]`

Get critical severity findings.

**Returns:**

`list[ExposureFinding]`

#### `high_findings(self) -> list[ExposureFinding]`

Get high severity findings.

**Returns:**

`list[ExposureFinding]`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## BaseExposureAnalyzer

**Inherits from:** ABC

Abstract base class for exposure analyzers.

Subclasses implement cloud-specific or resource-specific logic
for discovering publicly accessible resources.

### Properties

#### `config(self) -> ExposureConfig`

Get the analysis configuration.

**Returns:**

`ExposureConfig`

### Methods

#### `__init__(self, config: ExposureConfig | None)`

Initialize the exposure analyzer.

**Parameters:**

- `config` (`ExposureConfig | None`) - Optional configuration for analysis

#### `discover_public_assets(self) -> Iterator[PublicAsset]`

**Decorators:** @abstractmethod

Discover publicly accessible assets.  Yields: Public assets found

**Returns:**

`Iterator[PublicAsset]`

#### `analyze_asset(self, asset: PublicAsset) -> list[ExposureFinding]`

**Decorators:** @abstractmethod

Analyze a public asset for exposure findings.

**Parameters:**

- `asset` (`PublicAsset`) - Public asset to analyze

**Returns:**

`list[ExposureFinding]` - List of findings for this asset

#### `calculate_risk_score(self, exposure_type: ExposureType, data_classification: str | None, data_categories: list[str], access_method: str) -> float`

Calculate risk score for a public asset.

**Parameters:**

- `exposure_type` (`ExposureType`) - Type of exposure
- `data_classification` (`str | None`) - Data sensitivity level
- `data_categories` (`list[str]`) - Data categories present
- `access_method` (`str`) - How access is granted

**Returns:**

`float` - Risk score (0-100)

#### `calculate_severity(self, exposure_type: ExposureType, data_classification: str | None, has_sensitive_data: bool) -> ExposureSeverity`

Calculate severity for an exposure finding.

**Parameters:**

- `exposure_type` (`ExposureType`) - Type of exposure
- `data_classification` (`str | None`) - Data sensitivity level
- `has_sensitive_data` (`bool`) - Whether sensitive data is present

**Returns:**

`ExposureSeverity` - Severity level
