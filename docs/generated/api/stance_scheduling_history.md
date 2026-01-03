# stance.scheduling.history

Scan History for Mantissa Stance.

Provides scan history tracking, storage, and comparison capabilities
for analyzing security posture changes over time.

## Contents

### Classes

- [DiffType](#difftype)
- [ScanHistoryEntry](#scanhistoryentry)
- [ScanDiff](#scandiff)
- [ScanComparison](#scancomparison)
- [ScanHistoryManager](#scanhistorymanager)

## DiffType

**Inherits from:** Enum

Types of differences between scans.

## ScanHistoryEntry

**Tags:** dataclass

A single scan history entry.

Attributes:
    scan_id: Unique scan identifier
    timestamp: When the scan was performed
    config_name: Configuration used for the scan
    duration_seconds: How long the scan took
    assets_scanned: Number of assets scanned
    findings_total: Total number of findings
    findings_by_severity: Breakdown by severity level
    accounts_scanned: List of accounts scanned
    regions_scanned: List of regions scanned
    collectors_used: List of collectors used
    metadata: Additional scan metadata

### Attributes

| Name | Type | Default |
|------|------|---------|
| `scan_id` | `str` | - |
| `timestamp` | `datetime` | - |
| `config_name` | `str` | `default` |
| `duration_seconds` | `float` | `0.0` |
| `assets_scanned` | `int` | `0` |
| `findings_total` | `int` | `0` |
| `findings_by_severity` | `dict[(str, int)]` | `field(...)` |
| `accounts_scanned` | `list[str]` | `field(...)` |
| `regions_scanned` | `list[str]` | `field(...)` |
| `collectors_used` | `list[str]` | `field(...)` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> ScanHistoryEntry`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)

**Returns:**

`ScanHistoryEntry`

## ScanDiff

**Tags:** dataclass

Difference for a single finding between scans.

Attributes:
    finding_id: ID of the finding
    diff_type: Type of difference
    finding: The finding object
    previous_severity: Previous severity (if changed)
    current_severity: Current severity (if changed)
    previous_status: Previous status (if changed)
    current_status: Current status (if changed)

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding_id` | `str` | - |
| `diff_type` | `DiffType` | - |
| `finding` | `Finding | None` | - |
| `previous_severity` | `Severity | None` | - |
| `current_severity` | `Severity | None` | - |
| `previous_status` | `str | None` | - |
| `current_status` | `str | None` | - |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## ScanComparison

**Tags:** dataclass

Comparison between two scans.

Attributes:
    baseline_scan_id: ID of the baseline (previous) scan
    current_scan_id: ID of the current scan
    baseline_timestamp: When the baseline scan was performed
    current_timestamp: When the current scan was performed
    new_findings: Findings that appeared in current scan
    resolved_findings: Findings that were resolved
    unchanged_findings: Findings present in both
    severity_changes: Findings with severity changes
    status_changes: Findings with status changes
    summary: Summary statistics

### Attributes

| Name | Type | Default |
|------|------|---------|
| `baseline_scan_id` | `str` | - |
| `current_scan_id` | `str` | - |
| `baseline_timestamp` | `datetime` | - |
| `current_timestamp` | `datetime` | - |
| `new_findings` | `list[ScanDiff]` | `field(...)` |
| `resolved_findings` | `list[ScanDiff]` | `field(...)` |
| `unchanged_findings` | `list[ScanDiff]` | `field(...)` |
| `severity_changes` | `list[ScanDiff]` | `field(...)` |
| `status_changes` | `list[ScanDiff]` | `field(...)` |
| `summary` | `dict[(str, Any)]` | `field(...)` |

### Properties

#### `total_new(self) -> int`

Get count of new findings.

**Returns:**

`int`

#### `total_resolved(self) -> int`

Get count of resolved findings.

**Returns:**

`int`

#### `total_unchanged(self) -> int`

Get count of unchanged findings.

**Returns:**

`int`

#### `has_changes(self) -> bool`

Check if there are any changes.

**Returns:**

`bool`

#### `improvement_ratio(self) -> float`

Calculate improvement ratio.  Positive values indicate improvement (more resolved than new). Negative values indicate regression (more new than resolved).

**Returns:**

`float`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## ScanHistoryManager

Manages scan history and comparisons.

Provides storage, retrieval, and analysis of historical scan data.

### Methods

#### `__init__(self, storage_path: str = ~/.stance/history)`

Initialize the history manager.

**Parameters:**

- `storage_path` (`str`) - default: `~/.stance/history` - Path to store history data

#### `record_scan(self, scan_id: str, findings: FindingCollection, config_name: str = default, duration_seconds: float = 0.0, assets_scanned: int = 0, accounts: list[str] | None, regions: list[str] | None, collectors: list[str] | None, metadata: dict[(str, Any)] | None) -> ScanHistoryEntry`

Record a completed scan.

**Parameters:**

- `scan_id` (`str`) - Unique scan identifier
- `findings` (`FindingCollection`) - Findings from the scan
- `config_name` (`str`) - default: `default` - Configuration used
- `duration_seconds` (`float`) - default: `0.0` - Scan duration
- `assets_scanned` (`int`) - default: `0` - Number of assets scanned
- `accounts` (`list[str] | None`) - Accounts scanned
- `regions` (`list[str] | None`) - Regions scanned
- `collectors` (`list[str] | None`) - Collectors used
- `metadata` (`dict[(str, Any)] | None`) - Additional metadata

**Returns:**

`ScanHistoryEntry` - Created history entry

#### `get_history(self, limit: int | None, config_name: str | None, since: datetime | None) -> list[ScanHistoryEntry]`

Get scan history entries.

**Parameters:**

- `limit` (`int | None`) - Maximum number of entries to return
- `config_name` (`str | None`) - Filter by configuration name
- `since` (`datetime | None`) - Only include scans after this time

**Returns:**

`list[ScanHistoryEntry]` - List of history entries (most recent first)

#### `get_entry(self, scan_id: str) -> ScanHistoryEntry | None`

Get a specific history entry.

**Parameters:**

- `scan_id` (`str`)

**Returns:**

`ScanHistoryEntry | None`

#### `get_latest(self, config_name: str = default) -> ScanHistoryEntry | None`

Get the most recent scan for a configuration.

**Parameters:**

- `config_name` (`str`) - default: `default`

**Returns:**

`ScanHistoryEntry | None`

#### `get_findings(self, scan_id: str) -> FindingCollection | None`

Get findings for a specific scan.

**Parameters:**

- `scan_id` (`str`)

**Returns:**

`FindingCollection | None`

#### `compare_scans(self, baseline_scan_id: str, current_scan_id: str) -> ScanComparison | None`

Compare two scans.

**Parameters:**

- `baseline_scan_id` (`str`) - ID of the baseline (older) scan
- `current_scan_id` (`str`) - ID of the current (newer) scan

**Returns:**

`ScanComparison | None` - Comparison result, or None if scans not found

#### `compare_with_latest(self, scan_id: str, config_name: str = default) -> ScanComparison | None`

Compare a scan with the latest scan.

**Parameters:**

- `scan_id` (`str`) - ID of the baseline scan
- `config_name` (`str`) - default: `default` - Configuration to compare within

**Returns:**

`ScanComparison | None` - Comparison result

#### `get_trend(self, config_name: str = default, days: int = 30) -> list[dict[(str, Any)]]`

Get trend data for the specified period.

**Parameters:**

- `config_name` (`str`) - default: `default` - Configuration to analyze
- `days` (`int`) - default: `30` - Number of days to include

**Returns:**

`list[dict[(str, Any)]]` - List of trend data points

#### `cleanup_old_entries(self, retention_days: int = 90) -> int`

Remove history entries older than retention period.

**Parameters:**

- `retention_days` (`int`) - default: `90` - Number of days to retain

**Returns:**

`int` - Number of entries removed
