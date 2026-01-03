# stance.analytics.toxic_combinations

Toxic Combinations Detector for Mantissa Stance.

Identifies dangerous combinations of security conditions that, when present
together, create significantly elevated risk. Individual conditions may be
acceptable in isolation but become critical when combined.

Reference: Wiz "Toxic Combination" Analysis

## Contents

### Classes

- [ToxicCombinationType](#toxiccombinationtype)
- [ToxicCondition](#toxiccondition)
- [ToxicCombination](#toxiccombination)
- [ToxicCombinationDetector](#toxiccombinationdetector)

## ToxicCombinationType

**Inherits from:** Enum

Types of toxic combinations.

## ToxicCondition

**Tags:** dataclass

A single condition that contributes to a toxic combination.

Attributes:
    description: Human-readable description of the condition
    asset_id: ID of the asset with this condition
    evidence: Supporting evidence for the condition
    severity_contribution: How much this condition adds to overall severity

### Attributes

| Name | Type | Default |
|------|------|---------|
| `description` | `str` | - |
| `asset_id` | `str` | - |
| `evidence` | `dict[(str, Any)]` | `field(...)` |
| `severity_contribution` | `str` | `medium` |

## ToxicCombination

**Tags:** dataclass

A detected toxic combination of security conditions.

Attributes:
    id: Unique identifier for this combination
    combination_type: Type of toxic combination
    conditions: List of conditions that form this combination
    severity: Overall severity of the combination
    affected_assets: List of asset IDs affected
    description: Human-readable description
    impact: Potential impact description
    mitigation: Recommended mitigation steps
    score: Numeric risk score (0-100)

### Attributes

| Name | Type | Default |
|------|------|---------|
| `id` | `str` | - |
| `combination_type` | `ToxicCombinationType` | - |
| `conditions` | `list[ToxicCondition]` | - |
| `severity` | `Severity` | - |
| `affected_assets` | `list[str]` | - |
| `description` | `str` | - |
| `impact` | `str` | - |
| `mitigation` | `str` | - |
| `score` | `float` | `0.0` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## ToxicCombinationDetector

Detects toxic combinations of security conditions in cloud environments.

Analyzes asset graphs and findings to identify dangerous combinations
that create elevated security risk when present together.

### Methods

#### `__init__(self, graph: AssetGraph, findings: FindingCollection | None) -> None`

Initialize the toxic combination detector.

**Parameters:**

- `graph` (`AssetGraph`) - Asset graph to analyze
- `findings` (`FindingCollection | None`) - Optional findings collection for enrichment

**Returns:**

`None`

#### `detect(self) -> list[ToxicCombination]`

Detect all toxic combinations in the environment.

**Returns:**

`list[ToxicCombination]` - List of detected toxic combinations, sorted by severity
