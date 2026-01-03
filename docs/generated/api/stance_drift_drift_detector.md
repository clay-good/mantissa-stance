# stance.drift.drift_detector

Drift detection for Mantissa Stance.

Provides configuration drift detection, severity scoring,
and drift finding generation.

## Contents

### Classes

- [DriftType](#drifttype)
- [DriftSeverity](#driftseverity)
- [ConfigDifference](#configdifference)
- [DriftEvent](#driftevent)
- [DriftDetectionResult](#driftdetectionresult)
- [DriftDetector](#driftdetector)

## DriftType

**Inherits from:** Enum

Types of configuration drift.

## DriftSeverity

**Inherits from:** Enum

Severity levels for drift.

## ConfigDifference

**Tags:** dataclass

Single configuration difference.

Attributes:
    path: Configuration path (dot-separated)
    change_type: Type of change (added, removed, changed)
    baseline_value: Value in baseline
    current_value: Current value
    is_security_relevant: Whether change affects security
    severity: Severity of the change

### Attributes

| Name | Type | Default |
|------|------|---------|
| `path` | `str` | - |
| `change_type` | `str` | - |
| `baseline_value` | `Any` | - |
| `current_value` | `Any` | - |
| `is_security_relevant` | `bool` | `False` |
| `severity` | `DriftSeverity` | `"Attribute(value=Name(id='DriftSeverity', ctx=Load()), attr='INFO', ctx=Load())"` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## DriftEvent

**Tags:** dataclass

Configuration drift event.

Attributes:
    asset_id: Affected asset ID
    asset_type: Resource type
    cloud_provider: Cloud provider
    region: Asset region
    drift_type: Type of drift
    severity: Drift severity
    differences: List of configuration differences
    detected_at: When drift was detected
    baseline_id: Reference baseline ID
    description: Human-readable description

### Attributes

| Name | Type | Default |
|------|------|---------|
| `asset_id` | `str` | - |
| `asset_type` | `str` | - |
| `cloud_provider` | `str` | - |
| `region` | `str` | - |
| `drift_type` | `DriftType` | - |
| `severity` | `DriftSeverity` | - |
| `differences` | `list[ConfigDifference]` | - |
| `detected_at` | `datetime` | `field(...)` |
| `baseline_id` | `str` | `` |
| `description` | `str` | `` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

#### `to_finding(self) -> Finding`

Convert drift event to a finding.

**Returns:**

`Finding`

## DriftDetectionResult

**Tags:** dataclass

Result of drift detection.

Attributes:
    baseline_id: Baseline used for comparison
    detected_at: When detection was performed
    drift_events: List of drift events
    assets_checked: Number of assets checked
    assets_with_drift: Number of assets with drift
    summary: Summary statistics

### Attributes

| Name | Type | Default |
|------|------|---------|
| `baseline_id` | `str` | - |
| `detected_at` | `datetime` | - |
| `drift_events` | `list[DriftEvent]` | - |
| `assets_checked` | `int` | - |
| `assets_with_drift` | `int` | - |
| `summary` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

#### `get_findings(self) -> list[Finding]`

Convert all drift events to findings.

**Returns:**

`list[Finding]`

## DriftDetector

Detects configuration drift from baselines.

Compares current asset configurations against baselines
and generates drift events with severity scoring.

### Methods

#### `__init__(self, baseline_manager: BaselineManager | None, security_paths: set[str] | None)`

Initialize drift detector.

**Parameters:**

- `baseline_manager` (`BaselineManager | None`) - Baseline manager instance
- `security_paths` (`set[str] | None`) - Custom security-sensitive paths

#### `detect_drift(self, assets: AssetCollection | list[Asset], baseline_id: str | None) -> DriftDetectionResult`

Detect configuration drift.

**Parameters:**

- `assets` (`AssetCollection | list[Asset]`) - Current assets to check
- `baseline_id` (`str | None`) - Baseline to compare against (None = active baseline)

**Returns:**

`DriftDetectionResult` - Drift detection result

#### `add_security_path(self, path: str) -> None`

Add a security-sensitive path.

**Parameters:**

- `path` (`str`)

**Returns:**

`None`

#### `get_drift_summary(self, result: DriftDetectionResult) -> dict[(str, Any)]`

Generate drift summary for reporting.

**Parameters:**

- `result` (`DriftDetectionResult`) - Drift detection result

**Returns:**

`dict[(str, Any)]` - Summary dictionary
