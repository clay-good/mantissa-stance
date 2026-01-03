# stance.cli_diff

Findings diff command for Mantissa Stance.

Provides comparison between scan snapshots to show
new, resolved, and changed findings.

## Contents

### Classes

- [DiffChangeType](#diffchangetype)
- [FindingChange](#findingchange)
- [DiffSummary](#diffsummary)
- [DiffResult](#diffresult)
- [FindingsDiffer](#findingsdiffer)

### Functions

- [format_diff_table](#format_diff_table)
- [cmd_diff](#cmd_diff)

## DiffChangeType

**Inherits from:** Enum

Type of change in a finding.

## FindingChange

**Tags:** dataclass

Represents a change in a finding.

Attributes:
    finding_id: The finding identifier
    change_type: Type of change (new, resolved, severity_changed)
    severity: Current or last severity
    previous_severity: Previous severity (for changes)
    rule_id: Policy rule ID
    asset_id: Affected asset ID
    description: Finding description

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding_id` | `str` | - |
| `change_type` | `DiffChangeType` | - |
| `severity` | `str` | - |
| `previous_severity` | `str | None` | - |
| `rule_id` | `str | None` | - |
| `asset_id` | `str | None` | - |
| `description` | `str | None` | - |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## DiffSummary

**Tags:** dataclass

Summary of differences between two snapshots.

Attributes:
    baseline_snapshot: ID of baseline snapshot
    current_snapshot: ID of current snapshot
    baseline_timestamp: When baseline was created
    current_timestamp: When current was created
    new_findings: Number of new findings
    resolved_findings: Number of resolved findings
    severity_changes: Number of severity changes
    unchanged_findings: Number of unchanged findings
    new_by_severity: New findings by severity
    resolved_by_severity: Resolved findings by severity
    net_change: Net change in total findings
    is_improved: Whether posture improved

### Attributes

| Name | Type | Default |
|------|------|---------|
| `baseline_snapshot` | `str` | - |
| `current_snapshot` | `str` | - |
| `baseline_timestamp` | `datetime | None` | - |
| `current_timestamp` | `datetime | None` | - |
| `new_findings` | `int` | `0` |
| `resolved_findings` | `int` | `0` |
| `severity_changes` | `int` | `0` |
| `unchanged_findings` | `int` | `0` |
| `new_by_severity` | `dict[(str, int)]` | `field(...)` |
| `resolved_by_severity` | `dict[(str, int)]` | `field(...)` |
| `net_change` | `int` | `0` |
| `is_improved` | `bool` | `False` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## DiffResult

**Tags:** dataclass

Complete diff result between two snapshots.

Attributes:
    summary: DiffSummary with statistics
    changes: List of FindingChange objects
    baseline_findings: Dict of baseline findings by ID
    current_findings: Dict of current findings by ID

### Attributes

| Name | Type | Default |
|------|------|---------|
| `summary` | `DiffSummary` | - |
| `changes` | `list[FindingChange]` | `field(...)` |
| `baseline_findings` | `dict[(str, dict)]` | `field(...)` |
| `current_findings` | `dict[(str, dict)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

#### `get_new_findings(self) -> list[FindingChange]`

Get only new findings.

**Returns:**

`list[FindingChange]`

#### `get_resolved_findings(self) -> list[FindingChange]`

Get only resolved findings.

**Returns:**

`list[FindingChange]`

#### `get_severity_changes(self) -> list[FindingChange]`

Get only severity changes.

**Returns:**

`list[FindingChange]`

## FindingsDiffer

Compares findings between two scan snapshots.

Provides detailed diff information including new findings,
resolved findings, and severity changes.

### Properties

#### `storage(self)`

Lazy-load storage backend.

### Methods

#### `__init__(self, storage_type: str = local)`

Initialize the differ.

**Parameters:**

- `storage_type` (`str`) - default: `local` - Storage backend type

#### `diff(self, baseline_snapshot: str, current_snapshot: str | None) -> DiffResult`

Compare findings between two snapshots.

**Parameters:**

- `baseline_snapshot` (`str`) - Baseline snapshot ID
- `current_snapshot` (`str | None`) - Current snapshot ID (default: latest)

**Returns:**

`DiffResult` - DiffResult with changes

#### `diff_from_data(self, baseline_findings: list[dict], current_findings: list[dict], baseline_id: str = baseline, current_id: str = current) -> DiffResult`

Compare findings from provided data.

**Parameters:**

- `baseline_findings` (`list[dict]`) - List of baseline finding dicts
- `current_findings` (`list[dict]`) - List of current finding dicts
- `baseline_id` (`str`) - default: `baseline` - Baseline identifier
- `current_id` (`str`) - default: `current` - Current identifier

**Returns:**

`DiffResult` - DiffResult with changes

### `format_diff_table(diff: DiffResult, show_unchanged: bool = False) -> str`

Format diff result as a table.

**Parameters:**

- `diff` (`DiffResult`) - DiffResult to format
- `show_unchanged` (`bool`) - default: `False` - Include unchanged findings

**Returns:**

`str` - Formatted table string

### `cmd_diff(args: argparse.Namespace) -> int`

Execute findings diff command.

**Parameters:**

- `args` (`argparse.Namespace`) - Command-line arguments

**Returns:**

`int` - Exit code
