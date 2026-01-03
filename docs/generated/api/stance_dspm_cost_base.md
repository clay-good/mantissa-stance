# stance.dspm.cost.base

Base classes for DSPM cost analysis.

Provides abstract base class and common data models for analyzing
cloud storage costs and identifying cold/unused data.

## Contents

### Classes

- [FindingType](#findingtype)
- [StorageTier](#storagetier)
- [CostAnalysisConfig](#costanalysisconfig)
- [StorageMetrics](#storagemetrics)
- [ObjectAccessInfo](#objectaccessinfo)
- [ColdDataFinding](#colddatafinding)
- [CostAnalysisResult](#costanalysisresult)
- [BaseCostAnalyzer](#basecostanalyzer)

## FindingType

**Inherits from:** Enum

Types of cost analysis findings.

## StorageTier

**Inherits from:** Enum

Cloud storage tiers for cost estimation.

## CostAnalysisConfig

**Tags:** dataclass

Configuration for cost analysis.

Attributes:
    cold_data_days: Days without access to consider cold (default: 90)
    archive_candidate_days: Days without access to suggest archiving (default: 180)
    delete_candidate_days: Days without access to suggest deletion (default: 365)
    min_object_size_bytes: Minimum object size to analyze (skip small files)
    include_storage_class_analysis: Whether to suggest storage class changes
    cost_currency: Currency for cost estimates (default: USD)
    sample_size: Max objects to analyze per bucket (None for all)

### Attributes

| Name | Type | Default |
|------|------|---------|
| `cold_data_days` | `int` | `90` |
| `archive_candidate_days` | `int` | `180` |
| `delete_candidate_days` | `int` | `365` |
| `min_object_size_bytes` | `int` | `1024` |
| `include_storage_class_analysis` | `bool` | `True` |
| `cost_currency` | `str` | `USD` |
| `sample_size` | `int | None` | - |

## StorageMetrics

**Tags:** dataclass

Storage metrics for a bucket/container.

Attributes:
    bucket_name: Name of the bucket/container
    total_size_bytes: Total size in bytes
    total_objects: Total number of objects
    storage_tier: Current storage tier
    monthly_cost_estimate: Estimated monthly cost
    size_by_tier: Size breakdown by storage tier

### Attributes

| Name | Type | Default |
|------|------|---------|
| `bucket_name` | `str` | - |
| `total_size_bytes` | `int` | `0` |
| `total_objects` | `int` | `0` |
| `storage_tier` | `StorageTier` | `"Attribute(value=Name(id='StorageTier', ctx=Load()), attr='UNKNOWN', ctx=Load())"` |
| `monthly_cost_estimate` | `Decimal` | `Decimal(...)` |
| `size_by_tier` | `dict[(str, int)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert metrics to dictionary.

**Returns:**

`dict[(str, Any)]`

## ObjectAccessInfo

**Tags:** dataclass

Access information for a storage object.

Attributes:
    object_key: Object key/path
    size_bytes: Object size in bytes
    storage_class: Current storage class
    last_modified: Last modification time
    last_accessed: Last access time (if available)
    days_since_access: Days since last access
    days_since_modified: Days since last modification

### Attributes

| Name | Type | Default |
|------|------|---------|
| `object_key` | `str` | - |
| `size_bytes` | `int` | - |
| `storage_class` | `str` | `STANDARD` |
| `last_modified` | `datetime | None` | - |
| `last_accessed` | `datetime | None` | - |
| `days_since_access` | `int | None` | - |
| `days_since_modified` | `int | None` | - |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## ColdDataFinding

**Tags:** dataclass

A finding from cost analysis.

Attributes:
    finding_id: Unique identifier
    finding_type: Type of finding
    severity: Severity level (critical, high, medium, low, info)
    title: Short title
    description: Detailed description
    bucket_name: Affected bucket/container
    object_key: Affected object (if applicable)
    size_bytes: Size of affected data
    current_cost_monthly: Current monthly cost
    potential_savings_monthly: Potential monthly savings
    recommended_tier: Recommended storage tier
    recommended_action: Suggested action
    days_since_access: Days since last access
    metadata: Additional context
    detected_at: When finding was generated

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding_id` | `str` | - |
| `finding_type` | `FindingType` | - |
| `severity` | `str` | - |
| `title` | `str` | - |
| `description` | `str` | - |
| `bucket_name` | `str` | - |
| `object_key` | `str | None` | - |
| `size_bytes` | `int` | `0` |
| `current_cost_monthly` | `Decimal` | `Decimal(...)` |
| `potential_savings_monthly` | `Decimal` | `Decimal(...)` |
| `recommended_tier` | `StorageTier | None` | - |
| `recommended_action` | `str` | `` |
| `days_since_access` | `int | None` | - |
| `metadata` | `dict[(str, Any)]` | `field(...)` |
| `detected_at` | `datetime` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert finding to dictionary.

**Returns:**

`dict[(str, Any)]`

## CostAnalysisResult

**Tags:** dataclass

Result of cost analysis.

Attributes:
    analysis_id: Unique identifier
    bucket_name: Bucket/container analyzed
    config: Configuration used
    started_at: Analysis start time
    completed_at: Analysis completion time
    metrics: Storage metrics
    findings: List of findings
    total_size_bytes: Total data size analyzed
    cold_data_size_bytes: Size of cold data found
    total_monthly_cost: Total estimated monthly cost
    potential_monthly_savings: Potential monthly savings
    objects_analyzed: Number of objects analyzed
    errors: Errors encountered

### Attributes

| Name | Type | Default |
|------|------|---------|
| `analysis_id` | `str` | - |
| `bucket_name` | `str` | - |
| `config` | `CostAnalysisConfig` | - |
| `started_at` | `datetime` | - |
| `completed_at` | `datetime | None` | - |
| `metrics` | `StorageMetrics | None` | - |
| `findings` | `list[ColdDataFinding]` | `field(...)` |
| `total_size_bytes` | `int` | `0` |
| `cold_data_size_bytes` | `int` | `0` |
| `total_monthly_cost` | `Decimal` | `Decimal(...)` |
| `potential_monthly_savings` | `Decimal` | `Decimal(...)` |
| `objects_analyzed` | `int` | `0` |
| `errors` | `list[str]` | `field(...)` |

### Properties

#### `has_findings(self) -> bool`

Check if analysis has any findings.

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

#### `cold_data_percentage(self) -> float`

Get percentage of data that is cold.

**Returns:**

`float`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert result to dictionary.

**Returns:**

`dict[(str, Any)]`

## BaseCostAnalyzer

**Inherits from:** ABC

Abstract base class for cloud storage cost analyzers.

Subclasses implement cloud-specific logic for retrieving storage
metrics and access patterns.

All operations are read-only.

### Properties

#### `config(self) -> CostAnalysisConfig`

Get the analysis configuration.

**Returns:**

`CostAnalysisConfig`

### Methods

#### `__init__(self, config: CostAnalysisConfig | None)`

Initialize the cost analyzer.

**Parameters:**

- `config` (`CostAnalysisConfig | None`) - Optional configuration for cost analysis

#### `analyze_bucket(self, bucket_name: str) -> CostAnalysisResult`

**Decorators:** @abstractmethod

Analyze a bucket/container for cost optimization opportunities.

**Parameters:**

- `bucket_name` (`str`) - Name of the bucket to analyze

**Returns:**

`CostAnalysisResult` - Cost analysis result with findings and metrics

#### `get_storage_metrics(self, bucket_name: str) -> StorageMetrics`

**Decorators:** @abstractmethod

Get storage metrics for a bucket.

**Parameters:**

- `bucket_name` (`str`) - Name of the bucket

**Returns:**

`StorageMetrics` - Storage metrics including size, object count, costs

#### `get_object_access_info(self, bucket_name: str, object_key: str) -> ObjectAccessInfo | None`

**Decorators:** @abstractmethod

Get access information for a specific object.

**Parameters:**

- `bucket_name` (`str`) - Name of the bucket
- `object_key` (`str`) - Object key

**Returns:**

`ObjectAccessInfo | None` - Object access information or None if not available

#### `list_objects_with_access_info(self, bucket_name: str, prefix: str = ) -> Iterator[ObjectAccessInfo]`

**Decorators:** @abstractmethod

List objects with access information.

**Parameters:**

- `bucket_name` (`str`) - Name of the bucket
- `prefix` (`str`) - default: `` - Optional prefix filter

**Returns:**

`Iterator[ObjectAccessInfo]`
