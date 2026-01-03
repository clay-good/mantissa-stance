# stance.analytics.attack_paths

Attack Path Analyzer for Mantissa Stance.

Identifies potential attack paths through the cloud environment based on
asset relationships, network exposure, and security findings.

## Contents

### Classes

- [AttackPathType](#attackpathtype)
- [AttackPathStep](#attackpathstep)
- [AttackPath](#attackpath)
- [AttackPathAnalyzer](#attackpathanalyzer)

## AttackPathType

**Inherits from:** Enum

Types of attack paths.

## AttackPathStep

**Tags:** dataclass

A single step in an attack path.

Attributes:
    asset_id: ID of the asset in this step
    asset_name: Human-readable name
    resource_type: Type of resource
    action: Description of the attack action
    findings: Related security findings
    risk_level: Risk level of this step

### Attributes

| Name | Type | Default |
|------|------|---------|
| `asset_id` | `str` | - |
| `asset_name` | `str` | - |
| `resource_type` | `str` | - |
| `action` | `str` | - |
| `findings` | `list[str]` | `field(...)` |
| `risk_level` | `str` | `medium` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## AttackPath

**Tags:** dataclass

An identified attack path through the environment.

Attributes:
    id: Unique identifier
    path_type: Type of attack path
    steps: Ordered list of attack steps
    severity: Overall severity of the path
    description: Human-readable description
    mitigation: Suggested mitigation steps

### Attributes

| Name | Type | Default |
|------|------|---------|
| `id` | `str` | - |
| `path_type` | `AttackPathType` | - |
| `steps` | `list[AttackPathStep]` | - |
| `severity` | `Severity` | - |
| `description` | `str` | - |
| `mitigation` | `str` | `` |

### Properties

#### `length(self) -> int`

Get the number of steps in the path.

**Returns:**

`int`

#### `entry_point(self) -> AttackPathStep | None`

Get the entry point (first step).

**Returns:**

`AttackPathStep | None`

#### `target(self) -> AttackPathStep | None`

Get the target (last step).

**Returns:**

`AttackPathStep | None`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## AttackPathAnalyzer

Analyzes asset graphs to identify potential attack paths.

Considers network connectivity, IAM relationships, and security findings
to identify paths an attacker could exploit.

### Methods

#### `__init__(self, graph: AssetGraph, findings: FindingCollection | None) -> None`

Initialize the attack path analyzer.

**Parameters:**

- `graph` (`AssetGraph`) - Asset graph to analyze
- `findings` (`FindingCollection | None`) - Optional findings collection for enrichment

**Returns:**

`None`

#### `analyze(self) -> list[AttackPath]`

Analyze the graph and return all identified attack paths.

**Returns:**

`list[AttackPath]` - List of identified attack paths
