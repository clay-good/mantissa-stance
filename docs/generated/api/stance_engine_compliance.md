# stance.engine.compliance

Compliance calculator for Mantissa Stance.

Calculates compliance scores per framework based on
policy evaluations and findings.

## Contents

### Classes

- [ControlStatus](#controlstatus)
- [FrameworkScore](#frameworkscore)
- [ComplianceReport](#compliancereport)
- [ComplianceCalculator](#compliancecalculator)

## ControlStatus

**Tags:** dataclass

Status of a single compliance control.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `control_id` | `str` | - |
| `control_name` | `str` | - |
| `status` | `str` | - |
| `resources_evaluated` | `int` | - |
| `resources_compliant` | `int` | - |
| `resources_non_compliant` | `int` | - |
| `findings` | `list[str]` | `field(...)` |

## FrameworkScore

**Tags:** dataclass

Compliance score for a single framework.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `framework_id` | `str` | - |
| `framework_name` | `str` | - |
| `version` | `str` | - |
| `score_percentage` | `float` | - |
| `controls_passed` | `int` | - |
| `controls_failed` | `int` | - |
| `controls_total` | `int` | - |
| `control_statuses` | `list[ControlStatus]` | `field(...)` |

## ComplianceReport

**Tags:** dataclass

Complete compliance report across all frameworks.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `generated_at` | `datetime` | - |
| `snapshot_id` | `str` | - |
| `overall_score` | `float` | - |
| `frameworks` | `list[FrameworkScore]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert report to dictionary.

**Returns:**

`dict[(str, Any)]`

#### `to_json(self) -> str`

Convert report to JSON string.

**Returns:**

`str`

## ComplianceCalculator

Calculates compliance scores for frameworks.

Analyzes policies and findings to determine compliance
status for each control and framework.

### Methods

#### `calculate_scores(self, policies: Any, findings: Any, assets: Any, snapshot_id: str = ) -> ComplianceReport`

Calculate compliance scores for all frameworks.

**Parameters:**

- `policies` (`Any`) - Collection of policies with compliance mappings
- `findings` (`Any`) - Collection of findings from evaluation
- `assets` (`Any`) - Collection of assets evaluated
- `snapshot_id` (`str`) - default: `` - Snapshot ID for the report

**Returns:**

`ComplianceReport` - ComplianceReport with per-framework scores

#### `get_framework_score(self, framework_id: str, policies: Any, findings: Any, assets: Any) -> FrameworkScore`

Calculate score for a specific framework.

**Parameters:**

- `framework_id` (`str`) - Framework identifier
- `policies` (`Any`) - Collection of policies
- `findings` (`Any`) - Collection of findings
- `assets` (`Any`) - Collection of assets

**Returns:**

`FrameworkScore` - FrameworkScore for the framework

#### `get_control_status(self, framework_id: str, control_id: str, policies: Any, findings: Any) -> ControlStatus`

Get status for a specific control.

**Parameters:**

- `framework_id` (`str`) - Framework identifier
- `control_id` (`str`) - Control identifier
- `policies` (`Any`) - Collection of policies
- `findings` (`Any`) - Collection of findings

**Returns:**

`ControlStatus` - ControlStatus for the control
