# stance.dspm.extended.base

Base classes for DSPM extended source scanners.

Provides abstract base class and common data models for scanning
extended data sources (data warehouses, SaaS, databases).

## Contents

### Classes

- [ExtendedSourceType](#extendedsourcetype)
- [ExtendedScanConfig](#extendedscanconfig)
- [ExtendedScanFinding](#extendedscanfinding)
- [ExtendedScanSummary](#extendedscansummary)
- [ExtendedScanResult](#extendedscanresult)
- [BaseExtendedScanner](#baseextendedscanner)

## ExtendedSourceType

**Inherits from:** Enum

Types of extended data sources.

## ExtendedScanConfig

**Tags:** dataclass

Configuration for extended source scans.

Attributes:
    sample_size: Maximum number of rows/files to sample
    max_tables: Maximum number of tables to scan (for databases)
    max_columns_per_table: Maximum columns to sample per table
    include_schemas: Schemas to include (None for all)
    exclude_schemas: Schemas to exclude
    include_tables: Tables to include (None for all)
    exclude_tables: Tables to exclude
    file_extensions: File extensions to scan (for drive)
    timeout_seconds: Timeout for entire scan
    sample_rows_per_column: Rows to sample per column

### Attributes

| Name | Type | Default |
|------|------|---------|
| `sample_size` | `int` | `100` |
| `max_tables` | `int` | `50` |
| `max_columns_per_table` | `int` | `100` |
| `include_schemas` | `list[str] | None` | - |
| `exclude_schemas` | `list[str]` | `field(...)` |
| `include_tables` | `list[str] | None` | - |
| `exclude_tables` | `list[str]` | `field(...)` |
| `file_extensions` | `list[str] | None` | - |
| `timeout_seconds` | `int` | `600` |
| `sample_rows_per_column` | `int` | `100` |

## ExtendedScanFinding

**Tags:** dataclass

A sensitive data finding from an extended source scan.

Attributes:
    finding_id: Unique identifier
    finding_type: Type of finding
    severity: Severity level
    title: Short title
    description: Detailed description
    source_type: Type of source (snowflake, google_drive, etc.)
    source_location: Full path/identifier of the source
    object_type: Type of object (table, column, file, etc.)
    object_name: Name of the specific object
    classification_level: Data classification level
    categories: Data categories detected
    sample_matches: Sample of pattern matches
    remediation: Suggested remediation
    metadata: Additional context
    detected_at: When finding was created

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding_id` | `str` | - |
| `finding_type` | `str` | - |
| `severity` | `FindingSeverity` | - |
| `title` | `str` | - |
| `description` | `str` | - |
| `source_type` | `ExtendedSourceType` | - |
| `source_location` | `str` | - |
| `object_type` | `str` | - |
| `object_name` | `str` | - |
| `classification_level` | `ClassificationLevel` | - |
| `categories` | `list[DataCategory]` | `field(...)` |
| `sample_matches` | `list[dict[(str, Any)]]` | `field(...)` |
| `remediation` | `str` | `` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |
| `detected_at` | `datetime` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert finding to dictionary.

**Returns:**

`dict[(str, Any)]`

## ExtendedScanSummary

**Tags:** dataclass

Summary statistics for an extended source scan.

Attributes:
    total_objects_scanned: Number of objects scanned
    total_objects_skipped: Number of objects skipped
    total_rows_sampled: Total rows sampled (for databases)
    total_files_scanned: Total files scanned (for drive)
    total_findings: Number of findings
    findings_by_severity: Count by severity
    findings_by_category: Count by category
    scan_duration_seconds: Total duration
    errors: Errors encountered

### Attributes

| Name | Type | Default |
|------|------|---------|
| `total_objects_scanned` | `int` | `0` |
| `total_objects_skipped` | `int` | `0` |
| `total_rows_sampled` | `int` | `0` |
| `total_files_scanned` | `int` | `0` |
| `total_findings` | `int` | `0` |
| `findings_by_severity` | `dict[(str, int)]` | `field(...)` |
| `findings_by_category` | `dict[(str, int)]` | `field(...)` |
| `scan_duration_seconds` | `float` | `0.0` |
| `errors` | `list[str]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert summary to dictionary.

**Returns:**

`dict[(str, Any)]`

## ExtendedScanResult

**Tags:** dataclass

Complete result of an extended source scan.

Attributes:
    scan_id: Unique identifier
    source_type: Type of source scanned
    target: Target identifier
    config: Configuration used
    findings: List of findings
    summary: Summary statistics
    started_at: When scan started
    completed_at: When scan completed

### Attributes

| Name | Type | Default |
|------|------|---------|
| `scan_id` | `str` | - |
| `source_type` | `ExtendedSourceType` | - |
| `target` | `str` | - |
| `config` | `ExtendedScanConfig` | - |
| `findings` | `list[ExtendedScanFinding]` | `field(...)` |
| `summary` | `ExtendedScanSummary` | `field(...)` |
| `started_at` | `datetime` | `field(...)` |
| `completed_at` | `datetime | None` | - |

### Properties

#### `has_findings(self) -> bool`

Check if scan found any sensitive data.

**Returns:**

`bool`

#### `highest_severity(self) -> FindingSeverity | None`

Get the highest severity finding.

**Returns:**

`FindingSeverity | None`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert result to dictionary.

**Returns:**

`dict[(str, Any)]`

## BaseExtendedScanner

**Inherits from:** ABC

Abstract base class for extended source scanners.

Scanners sample data from extended sources (data warehouses, SaaS,
databases) and detect sensitive data patterns.

All scanners are read-only and do not modify source data.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `source_type` | `ExtendedSourceType` | - |

### Properties

#### `config(self) -> ExtendedScanConfig`

Get scan configuration.

**Returns:**

`ExtendedScanConfig`

#### `detector(self) -> SensitiveDataDetector`

Get sensitive data detector.

**Returns:**

`SensitiveDataDetector`

### Methods

#### `__init__(self, config: ExtendedScanConfig | None)`

Initialize the scanner.

**Parameters:**

- `config` (`ExtendedScanConfig | None`) - Optional scan configuration

#### `scan(self, target: str) -> ExtendedScanResult`

**Decorators:** @abstractmethod

Scan a target for sensitive data.

**Parameters:**

- `target` (`str`) - Target identifier (database name, drive folder, etc.)

**Returns:**

`ExtendedScanResult` - Scan result with findings and summary

#### `test_connection(self) -> bool`

**Decorators:** @abstractmethod

Test connection to the data source.

**Returns:**

`bool` - True if connection successful

#### `list_scannable_objects(self, target: str) -> list[dict[(str, Any)]]`

**Decorators:** @abstractmethod

List objects that can be scanned in the target.

**Parameters:**

- `target` (`str`) - Target identifier

**Returns:**

`list[dict[(str, Any)]]` - List of scannable object metadata
