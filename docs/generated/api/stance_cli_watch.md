# stance.cli_watch

Watch mode for continuous monitoring in Mantissa Stance.

Provides continuous scanning with real-time updates and
notifications when security posture changes.

## Contents

### Classes

- [WatchConfig](#watchconfig)
- [ScanSnapshot](#scansnapshot)
- [ScanDelta](#scandelta)
- [WatchMode](#watchmode)

### Functions

- [cmd_watch](#cmd_watch)

## WatchConfig

**Tags:** dataclass

Configuration for watch mode.

Attributes:
    interval_seconds: Time between scans
    collectors: Specific collectors to run (None = all)
    policies: Specific policies to evaluate (None = all)
    notify_on_change: Send notifications on changes
    show_summary: Display summary after each scan
    show_diff: Display changes from previous scan
    max_iterations: Maximum scans (0 = unlimited)
    quiet: Suppress non-essential output
    output_format: Output format (table/json)

### Attributes

| Name | Type | Default |
|------|------|---------|
| `interval_seconds` | `int` | `300` |
| `collectors` | `list[str] | None` | - |
| `policies` | `list[str] | None` | - |
| `notify_on_change` | `bool` | `False` |
| `show_summary` | `bool` | `True` |
| `show_diff` | `bool` | `True` |
| `max_iterations` | `int` | `0` |
| `quiet` | `bool` | `False` |
| `output_format` | `str` | `table` |

## ScanSnapshot

**Tags:** dataclass

Snapshot of scan results for comparison.

Attributes:
    timestamp: When the scan was performed
    snapshot_id: Unique identifier for this snapshot
    total_findings: Total number of findings
    findings_by_severity: Findings count by severity
    critical_findings: List of critical finding IDs
    finding_ids: Set of all finding IDs

### Attributes

| Name | Type | Default |
|------|------|---------|
| `timestamp` | `datetime` | - |
| `snapshot_id` | `str` | - |
| `total_findings` | `int` | `0` |
| `findings_by_severity` | `dict[(str, int)]` | `field(...)` |
| `critical_findings` | `list[str]` | `field(...)` |
| `finding_ids` | `set[str]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## ScanDelta

**Tags:** dataclass

Changes between two scan snapshots.

Attributes:
    previous: Previous snapshot
    current: Current snapshot
    new_findings: Count of new findings
    resolved_findings: Count of resolved findings
    new_critical: Count of new critical findings
    severity_changes: Changes by severity
    is_improved: Whether posture improved
    is_degraded: Whether posture degraded

### Attributes

| Name | Type | Default |
|------|------|---------|
| `previous` | `ScanSnapshot` | - |
| `current` | `ScanSnapshot` | - |
| `new_findings` | `int` | `0` |
| `resolved_findings` | `int` | `0` |
| `new_critical` | `int` | `0` |
| `severity_changes` | `dict[(str, int)]` | `field(...)` |
| `is_improved` | `bool` | `False` |
| `is_degraded` | `bool` | `False` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## WatchMode

Continuous monitoring mode for Stance.

Runs periodic scans and tracks changes over time,
providing real-time visibility into security posture.

### Properties

#### `config(self) -> WatchConfig`

Get watch configuration.

**Returns:**

`WatchConfig`

#### `is_running(self) -> bool`

Check if watch mode is running.

**Returns:**

`bool`

#### `iteration_count(self) -> int`

Get current iteration count.

**Returns:**

`int`

#### `snapshots(self) -> list[ScanSnapshot]`

Get all snapshots.

**Returns:**

`list[ScanSnapshot]`

#### `last_snapshot(self) -> ScanSnapshot | None`

Get most recent snapshot.

**Returns:**

`ScanSnapshot | None`

### Methods

#### `__init__(self, config: WatchConfig | None)`

Initialize watch mode.

**Parameters:**

- `config` (`WatchConfig | None`) - Watch configuration

#### `add_callback(self, callback: Callable[([ScanSnapshot, ScanDelta | None], None)]) -> None`

Add a callback to be called after each scan.

**Parameters:**

- `callback` (`Callable[([ScanSnapshot, ScanDelta | None], None)]`) - Function receiving snapshot and optional delta

**Returns:**

`None`

#### `start(self) -> None`

Start watch mode.  Runs continuously until stop() is called or max_iterations reached.

**Returns:**

`None`

#### `stop(self) -> None`

Stop watch mode.

**Returns:**

`None`

### `cmd_watch(args: argparse.Namespace) -> int`

Execute watch mode command.

**Parameters:**

- `args` (`argparse.Namespace`) - Command-line arguments

**Returns:**

`int` - Exit code
