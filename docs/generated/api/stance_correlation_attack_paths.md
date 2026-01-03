# stance.correlation.attack_paths

Attack path analysis for Mantissa Stance.

Identifies potential attack paths through cloud infrastructure
based on findings, asset relationships, and network topology.

## Contents

### Classes

- [AttackPathType](#attackpathtype)
- [ExposureLevel](#exposurelevel)
- [AttackStep](#attackstep)
- [AttackPath](#attackpath)
- [AttackPathAnalysisResult](#attackpathanalysisresult)
- [AttackPathAnalyzer](#attackpathanalyzer)

## AttackPathType

**Inherits from:** Enum

Types of attack paths.

## ExposureLevel

**Inherits from:** Enum

Asset exposure levels.

## AttackStep

**Tags:** dataclass

A single step in an attack path.

Attributes:
    order: Step order in the path
    asset_id: Asset involved in this step
    asset_name: Human-readable asset name
    finding_id: Related finding (if any)
    action: Attack action taken
    technique: MITRE ATT&CK technique (if applicable)
    exposure: Exposure level of the asset
    risk_contribution: Risk contribution of this step

### Attributes

| Name | Type | Default |
|------|------|---------|
| `order` | `int` | - |
| `asset_id` | `str` | - |
| `asset_name` | `str` | - |
| `finding_id` | `str | None` | - |
| `action` | `str` | `` |
| `technique` | `str` | `` |
| `exposure` | `ExposureLevel` | `"Attribute(value=Name(id='ExposureLevel', ctx=Load()), attr='INTERNAL', ctx=Load())"` |
| `risk_contribution` | `float` | `0.0` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## AttackPath

**Tags:** dataclass

A potential attack path through cloud infrastructure.

Attributes:
    id: Unique path identifier
    path_type: Type of attack path
    steps: Ordered list of attack steps
    entry_point: Initial access asset
    target: Final target asset
    total_risk_score: Combined risk score
    likelihood: Estimated likelihood (0-1)
    impact: Estimated impact (0-1)
    findings: Findings that enable this path
    mitigations: Recommended mitigations

### Attributes

| Name | Type | Default |
|------|------|---------|
| `id` | `str` | - |
| `path_type` | `AttackPathType` | - |
| `steps` | `list[AttackStep]` | - |
| `entry_point` | `str` | - |
| `target` | `str` | - |
| `total_risk_score` | `float` | `0.0` |
| `likelihood` | `float` | `0.0` |
| `impact` | `float` | `0.0` |
| `findings` | `list[str]` | `field(...)` |
| `mitigations` | `list[str]` | `field(...)` |

### Properties

#### `length(self) -> int`

Get path length.

**Returns:**

`int`

#### `risk_priority(self) -> float`

Calculate risk priority (likelihood * impact).

**Returns:**

`float`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## AttackPathAnalysisResult

**Tags:** dataclass

Result of attack path analysis.

Attributes:
    paths: Identified attack paths
    high_risk_paths: Paths with high risk priority
    stats: Analysis statistics

### Attributes

| Name | Type | Default |
|------|------|---------|
| `paths` | `list[AttackPath]` | `field(...)` |
| `high_risk_paths` | `list[AttackPath]` | `field(...)` |
| `stats` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## AttackPathAnalyzer

Analyzes findings and assets to identify attack paths.

Identifies potential attack paths including:
- Internet to internal resource paths
- Privilege escalation chains
- Lateral movement opportunities
- Data exfiltration paths

Example:
    >>> analyzer = AttackPathAnalyzer()
    >>> result = analyzer.analyze(findings, assets)
    >>> for path in result.high_risk_paths:
    ...     print(f"Path: {path.entry_point} -> {path.target}")

### Methods

#### `__init__(self, max_path_length: int = 5, min_risk_threshold: float = 0.3) -> None`

Initialize the attack path analyzer.

**Parameters:**

- `max_path_length` (`int`) - default: `5` - Maximum steps in an attack path
- `min_risk_threshold` (`float`) - default: `0.3` - Minimum risk to include a path

**Returns:**

`None`

#### `analyze(self, findings: FindingCollection | list[Finding], assets: AssetCollection | list[Asset]) -> AttackPathAnalysisResult`

Analyze findings and assets to identify attack paths.

**Parameters:**

- `findings` (`FindingCollection | list[Finding]`) - Security findings
- `assets` (`AssetCollection | list[Asset]`) - Asset inventory

**Returns:**

`AttackPathAnalysisResult` - AttackPathAnalysisResult with identified paths
