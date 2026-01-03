# stance.exposure.sensitive

Sensitive Data Exposure Correlation for Exposure Management.

Cross-references publicly accessible resources with DSPM scan findings
to identify critical exposures where sensitive data is publicly accessible.

## Contents

### Classes

- [SensitiveExposureType](#sensitiveexposuretype)
- [ExposureRiskLevel](#exposurerisklevel)
- [SensitiveExposureConfig](#sensitiveexposureconfig)
- [SensitiveDataMatch](#sensitivedatamatch)
- [SensitiveExposureFinding](#sensitiveexposurefinding)
- [SensitiveExposureSummary](#sensitiveexposuresummary)
- [SensitiveExposureResult](#sensitiveexposureresult)
- [SensitiveDataExposureAnalyzer](#sensitivedataexposureanalyzer)

### Functions

- [correlate_exposure_with_dspm](#correlate_exposure_with_dspm)

## SensitiveExposureType

**Inherits from:** Enum

Types of sensitive data exposure.

## ExposureRiskLevel

**Inherits from:** Enum

Risk levels for sensitive data exposure.

### Properties

#### `rank(self) -> int`

Numeric rank for comparison.

**Returns:**

`int`

## SensitiveExposureConfig

**Tags:** dataclass

Configuration for sensitive data exposure analysis.

Attributes:
    min_classification_level: Minimum classification to consider sensitive
    include_pii: Include PII findings
    include_pci: Include PCI findings
    include_phi: Include PHI findings
    include_credentials: Include credential findings
    include_financial: Include financial data findings
    prioritize_internet_facing: Prioritize internet-facing exposures
    generate_remediation: Generate remediation recommendations

### Attributes

| Name | Type | Default |
|------|------|---------|
| `min_classification_level` | `ClassificationLevel` | `"Attribute(value=Name(id='ClassificationLevel', ctx=Load()), attr='INTERNAL', ctx=Load())"` |
| `include_pii` | `bool` | `True` |
| `include_pci` | `bool` | `True` |
| `include_phi` | `bool` | `True` |
| `include_credentials` | `bool` | `True` |
| `include_financial` | `bool` | `True` |
| `prioritize_internet_facing` | `bool` | `True` |
| `generate_remediation` | `bool` | `True` |

## SensitiveDataMatch

**Tags:** dataclass

A match between a public asset and sensitive data finding.

Attributes:
    asset_id: Public asset identifier
    asset_name: Public asset name
    finding_id: DSPM finding identifier
    storage_location: Full path to the sensitive data
    classification_level: Data classification level
    data_categories: Categories of sensitive data found
    match_count: Number of sensitive patterns matched
    sample_data: Sample of matched patterns (redacted)
    detection_confidence: Confidence level of detection

### Attributes

| Name | Type | Default |
|------|------|---------|
| `asset_id` | `str` | - |
| `asset_name` | `str` | - |
| `finding_id` | `str` | - |
| `storage_location` | `str` | - |
| `classification_level` | `ClassificationLevel` | - |
| `data_categories` | `list[DataCategory]` | `field(...)` |
| `match_count` | `int` | `0` |
| `sample_data` | `list[dict[(str, Any)]]` | `field(...)` |
| `detection_confidence` | `float` | `1.0` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## SensitiveExposureFinding

**Tags:** dataclass

A finding of sensitive data being publicly exposed.

Attributes:
    finding_id: Unique identifier
    exposure_type: Type of sensitive exposure
    risk_level: Risk level
    title: Short title
    description: Detailed description
    asset_id: Affected public asset ID
    asset_name: Public asset name
    exposure_type_asset: Type of public exposure (bucket, instance, etc.)
    cloud_provider: Cloud provider
    region: Region
    classification_level: Highest classification level exposed
    data_categories: Data categories exposed
    data_matches: Detailed match information
    total_findings_count: Total number of DSPM findings
    risk_score: Numeric risk score (0-100)
    recommended_action: Suggested remediation
    compliance_impact: Compliance frameworks affected
    metadata: Additional context
    detected_at: When finding was generated

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding_id` | `str` | - |
| `exposure_type` | `SensitiveExposureType` | - |
| `risk_level` | `ExposureRiskLevel` | - |
| `title` | `str` | - |
| `description` | `str` | - |
| `asset_id` | `str` | - |
| `asset_name` | `str` | - |
| `exposure_type_asset` | `ExposureType` | - |
| `cloud_provider` | `str` | - |
| `region` | `str` | - |
| `classification_level` | `ClassificationLevel` | - |
| `data_categories` | `list[DataCategory]` | `field(...)` |
| `data_matches` | `list[SensitiveDataMatch]` | `field(...)` |
| `total_findings_count` | `int` | `0` |
| `risk_score` | `float` | `0.0` |
| `recommended_action` | `str` | `` |
| `compliance_impact` | `list[str]` | `field(...)` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |
| `detected_at` | `datetime` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## SensitiveExposureSummary

**Tags:** dataclass

Summary statistics for sensitive data exposure analysis.

Attributes:
    total_public_assets: Total public assets analyzed
    assets_with_sensitive_data: Assets with sensitive data exposed
    total_sensitive_findings: Total sensitive data findings
    critical_exposures: Count of critical risk exposures
    high_exposures: Count of high risk exposures
    exposures_by_type: Count by exposure type
    exposures_by_category: Count by data category
    exposures_by_cloud: Count by cloud provider
    highest_risk_assets: Top risk assets
    compliance_frameworks_impacted: Affected compliance frameworks
    average_risk_score: Average risk score

### Attributes

| Name | Type | Default |
|------|------|---------|
| `total_public_assets` | `int` | `0` |
| `assets_with_sensitive_data` | `int` | `0` |
| `total_sensitive_findings` | `int` | `0` |
| `critical_exposures` | `int` | `0` |
| `high_exposures` | `int` | `0` |
| `exposures_by_type` | `dict[(str, int)]` | `field(...)` |
| `exposures_by_category` | `dict[(str, int)]` | `field(...)` |
| `exposures_by_cloud` | `dict[(str, int)]` | `field(...)` |
| `highest_risk_assets` | `list[str]` | `field(...)` |
| `compliance_frameworks_impacted` | `list[str]` | `field(...)` |
| `average_risk_score` | `float` | `0.0` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## SensitiveExposureResult

**Tags:** dataclass

Result of sensitive data exposure analysis.

Attributes:
    analysis_id: Unique identifier
    config: Configuration used
    started_at: Analysis start time
    completed_at: Analysis completion time
    public_assets_analyzed: Number of public assets analyzed
    dspm_findings_correlated: Number of DSPM findings correlated
    exposures: List of sensitive exposure findings
    summary: Summary statistics
    errors: Errors encountered

### Attributes

| Name | Type | Default |
|------|------|---------|
| `analysis_id` | `str` | - |
| `config` | `SensitiveExposureConfig` | - |
| `started_at` | `datetime` | - |
| `completed_at` | `datetime | None` | - |
| `public_assets_analyzed` | `int` | `0` |
| `dspm_findings_correlated` | `int` | `0` |
| `exposures` | `list[SensitiveExposureFinding]` | `field(...)` |
| `summary` | `SensitiveExposureSummary` | `field(...)` |
| `errors` | `list[str]` | `field(...)` |

### Properties

#### `has_exposures(self) -> bool`

Check if any sensitive exposures were found.

**Returns:**

`bool`

#### `critical_exposures(self) -> list[SensitiveExposureFinding]`

Get critical risk exposures.

**Returns:**

`list[SensitiveExposureFinding]`

#### `high_exposures(self) -> list[SensitiveExposureFinding]`

Get high risk exposures.

**Returns:**

`list[SensitiveExposureFinding]`

#### `exposures_by_type(self) -> dict[(str, int)]`

Count exposures by type.

**Returns:**

`dict[(str, int)]`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## SensitiveDataExposureAnalyzer

Analyzer for correlating public assets with sensitive data findings.

Cross-references publicly accessible resources with DSPM scan results
to identify critical exposures where sensitive data is publicly accessible.

### Properties

#### `config(self) -> SensitiveExposureConfig`

Get the analysis configuration.

**Returns:**

`SensitiveExposureConfig`

### Methods

#### `__init__(self, config: SensitiveExposureConfig | None)`

Initialize the sensitive data exposure analyzer.

**Parameters:**

- `config` (`SensitiveExposureConfig | None`) - Optional configuration

#### `register_public_assets(self, assets: list[PublicAsset]) -> None`

Register public assets for correlation.

**Parameters:**

- `assets` (`list[PublicAsset]`) - List of public assets

**Returns:**

`None`

#### `register_inventory_result(self, result: ExposureInventoryResult) -> None`

Register an exposure inventory result.

**Parameters:**

- `result` (`ExposureInventoryResult`) - Exposure inventory result

**Returns:**

`None`

#### `register_dspm_scan_result(self, result: ScanResult) -> None`

Register a DSPM scan result for correlation.

**Parameters:**

- `result` (`ScanResult`) - DSPM scan result

**Returns:**

`None`

#### `register_dspm_findings(self, asset_id: str, findings: list[ScanFinding]) -> None`

Register DSPM findings directly for an asset.

**Parameters:**

- `asset_id` (`str`) - Asset identifier
- `findings` (`list[ScanFinding]`) - List of scan findings

**Returns:**

`None`

#### `analyze(self) -> SensitiveExposureResult`

Analyze sensitive data exposure across all registered data.

**Returns:**

`SensitiveExposureResult` - Complete analysis result

#### `analyze_asset(self, asset: PublicAsset, dspm_findings: list[ScanFinding]) -> SensitiveExposureFinding | None`

Analyze a single public asset with its DSPM findings.

**Parameters:**

- `asset` (`PublicAsset`) - Public asset to analyze
- `dspm_findings` (`list[ScanFinding]`) - DSPM findings for this asset

**Returns:**

`SensitiveExposureFinding | None` - Sensitive exposure finding or None if no exposure

#### `get_critical_exposures(self) -> list[SensitiveExposureFinding]`

Get only critical risk exposures.

**Returns:**

`list[SensitiveExposureFinding]` - List of critical exposures

#### `get_exposures_by_category(self, category: DataCategory) -> list[SensitiveExposureFinding]`

Get exposures filtered by data category.

**Parameters:**

- `category` (`DataCategory`) - Data category to filter by

**Returns:**

`list[SensitiveExposureFinding]` - List of exposures with the specified category

#### `get_exposures_by_classification(self, classification: ClassificationLevel) -> list[SensitiveExposureFinding]`

Get exposures filtered by classification level.

**Parameters:**

- `classification` (`ClassificationLevel`) - Classification level to filter by

**Returns:**

`list[SensitiveExposureFinding]` - List of exposures with the specified or higher classification

### `correlate_exposure_with_dspm(inventory_result: ExposureInventoryResult, dspm_results: list[ScanResult], config: SensitiveExposureConfig | None) -> SensitiveExposureResult`

Convenience function to correlate exposure inventory with DSPM results.

**Parameters:**

- `inventory_result` (`ExposureInventoryResult`) - Exposure inventory result
- `dspm_results` (`list[ScanResult]`) - List of DSPM scan results
- `config` (`SensitiveExposureConfig | None`) - Optional configuration

**Returns:**

`SensitiveExposureResult` - Sensitive exposure analysis result
