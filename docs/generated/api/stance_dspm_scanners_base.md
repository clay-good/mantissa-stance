# stance.dspm.scanners.base

Base classes for DSPM storage scanners.

Provides abstract base class and common data models for scanning
cloud storage services to detect sensitive data.

## Contents

### Classes

- [FindingSeverity](#findingseverity)
- [ScanConfig](#scanconfig)
- [ScanFinding](#scanfinding)
- [ScanSummary](#scansummary)
- [ScanResult](#scanresult)
- [BaseDataScanner](#basedatascanner)

## FindingSeverity

**Inherits from:** Enum

Severity levels for DSPM findings.

### Class Methods

#### `from_classification(cls, level: ClassificationLevel) -> 'FindingSeverity'`

**Decorators:** @classmethod

Map classification level to finding severity.

**Parameters:**

- `level` (`ClassificationLevel`)

**Returns:**

`'FindingSeverity'`

## ScanConfig

**Tags:** dataclass

Configuration for a DSPM storage scan.

Attributes:
    sample_size: Maximum number of objects to sample (None for all)
    max_object_size_bytes: Maximum object size to scan (skip larger)
    file_extensions: File extensions to scan (None for all)
    exclude_patterns: Glob patterns to exclude
    include_metadata: Whether to scan object metadata
    timeout_seconds: Timeout for entire scan operation
    content_sample_bytes: Bytes to read from each object for sampling

### Attributes

| Name | Type | Default |
|------|------|---------|
| `sample_size` | `int | None` | `100` |
| `max_object_size_bytes` | `int` | `'BinOp(left=BinOp(left=Constant(value=10), op=Mult(), right=Constant(value=1024)), op=Mult(), right=Constant(value=1024))'` |
| `file_extensions` | `list[str] | None` | - |
| `exclude_patterns` | `list[str]` | `field(...)` |
| `include_metadata` | `bool` | `True` |
| `timeout_seconds` | `int` | `300` |
| `content_sample_bytes` | `int` | `'BinOp(left=Constant(value=64), op=Mult(), right=Constant(value=1024))'` |

## ScanFinding

**Tags:** dataclass

A sensitive data finding from a storage scan.

Attributes:
    finding_id: Unique identifier for this finding
    finding_type: Type of finding (e.g., SENSITIVE_DATA_DETECTED)
    severity: Severity level
    title: Short title for the finding
    description: Detailed description
    storage_location: Full path to the affected object
    bucket_name: Name of the bucket/container
    object_key: Object key within the bucket
    classification_level: Data classification level detected
    categories: Data categories detected
    sample_matches: Sample of pattern matches found
    remediation: Suggested remediation steps
    metadata: Additional context metadata
    detected_at: When the finding was created

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding_id` | `str` | - |
| `finding_type` | `str` | - |
| `severity` | `FindingSeverity` | - |
| `title` | `str` | - |
| `description` | `str` | - |
| `storage_location` | `str` | - |
| `bucket_name` | `str` | - |
| `object_key` | `str` | - |
| `classification_level` | `ClassificationLevel` | - |
| `categories` | `list[DataCategory]` | `field(...)` |
| `sample_matches` | `list[dict[(str, Any)]]` | `field(...)` |
| `remediation` | `str` | `` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |
| `detected_at` | `datetime` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert finding to dictionary representation.

**Returns:**

`dict[(str, Any)]`

## ScanSummary

**Tags:** dataclass

Summary statistics for a storage scan.

Attributes:
    total_objects_scanned: Number of objects scanned
    total_objects_skipped: Number of objects skipped
    total_bytes_scanned: Total bytes of data scanned
    total_findings: Number of findings generated
    findings_by_severity: Count of findings by severity
    findings_by_category: Count of findings by data category
    scan_duration_seconds: Total scan duration
    errors: List of errors encountered

### Attributes

| Name | Type | Default |
|------|------|---------|
| `total_objects_scanned` | `int` | `0` |
| `total_objects_skipped` | `int` | `0` |
| `total_bytes_scanned` | `int` | `0` |
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

## ScanResult

**Tags:** dataclass

Complete result of a DSPM storage scan.

Attributes:
    scan_id: Unique identifier for this scan
    storage_type: Type of storage scanned (s3, gcs, azure_blob)
    target: Target storage identifier (bucket name, etc.)
    config: Configuration used for the scan
    findings: List of sensitive data findings
    summary: Summary statistics
    started_at: When the scan started
    completed_at: When the scan completed

### Attributes

| Name | Type | Default |
|------|------|---------|
| `scan_id` | `str` | - |
| `storage_type` | `str` | - |
| `target` | `str` | - |
| `config` | `ScanConfig` | - |
| `findings` | `list[ScanFinding]` | `field(...)` |
| `summary` | `ScanSummary` | `field(...)` |
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

## BaseDataScanner

**Inherits from:** ABC

Abstract base class for DSPM storage scanners.

Scanners sample data from cloud storage services and use the
sensitive data detector to identify PII, PCI, PHI, and other
sensitive information.

All scanners are read-only and do not modify stored data.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `storage_type` | `str` | `base` |

### Properties

#### `config(self) -> ScanConfig`

Get the scan configuration.

**Returns:**

`ScanConfig`

#### `detector(self) -> SensitiveDataDetector`

Get the sensitive data detector.

**Returns:**

`SensitiveDataDetector`

### Methods

#### `__init__(self, config: ScanConfig | None)`

Initialize the scanner.

**Parameters:**

- `config` (`ScanConfig | None`) - Optional scan configuration

#### `scan_bucket(self, bucket_name: str) -> ScanResult`

**Decorators:** @abstractmethod

Scan a storage bucket/container for sensitive data.

**Parameters:**

- `bucket_name` (`str`) - Name of the bucket to scan

**Returns:**

`ScanResult` - Scan result with findings and summary

#### `scan_object(self, bucket_name: str, object_key: str) -> ScanFinding | None`

**Decorators:** @abstractmethod

Scan a specific object for sensitive data.

**Parameters:**

- `bucket_name` (`str`) - Name of the bucket
- `object_key` (`str`) - Key of the object to scan

**Returns:**

`ScanFinding | None` - Finding if sensitive data detected, None otherwise

#### `list_objects(self, bucket_name: str, prefix: str = ) -> Iterator[dict[(str, Any)]]`

**Decorators:** @abstractmethod

List objects in a bucket.

**Parameters:**

- `bucket_name` (`str`) - Name of the bucket
- `prefix` (`str`) - default: `` - Optional prefix to filter objects

**Returns:**

`Iterator[dict[(str, Any)]]`

#### `get_object_content(self, bucket_name: str, object_key: str, max_bytes: int | None) -> bytes | None`

**Decorators:** @abstractmethod

Get object content (or sample).

**Parameters:**

- `bucket_name` (`str`) - Name of the bucket
- `object_key` (`str`) - Key of the object
- `max_bytes` (`int | None`) - Maximum bytes to read

**Returns:**

`bytes | None` - Object content as bytes, or None if not accessible

#### `get_bucket_metadata(self, bucket_name: str) -> dict[(str, Any)]`

**Decorators:** @abstractmethod

Get bucket/container metadata.

**Parameters:**

- `bucket_name` (`str`) - Name of the bucket

**Returns:**

`dict[(str, Any)]` - Bucket metadata including encryption, public access, etc.
