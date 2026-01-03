# stance.correlation.correlator

Finding correlator for Mantissa Stance.

Correlates security findings by asset, network path, and other
relationships to identify attack chains and aggregate risk.

## Contents

### Classes

- [CorrelatedFinding](#correlatedfinding)
- [CorrelationGroup](#correlationgroup)
- [CorrelationResult](#correlationresult)
- [FindingCorrelator](#findingcorrelator)

## CorrelatedFinding

**Tags:** dataclass

A finding with its correlation context.

Attributes:
    finding: The original finding
    related_findings: List of related finding IDs
    correlation_type: Type of correlation (asset, network, rule, cve)
    correlation_score: Strength of correlation (0-1)
    correlation_reason: Human-readable correlation reason

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding` | `Finding` | - |
| `related_findings` | `list[str]` | `field(...)` |
| `correlation_type` | `str` | `` |
| `correlation_score` | `float` | `0.0` |
| `correlation_reason` | `str` | `` |

## CorrelationGroup

**Tags:** dataclass

A group of correlated findings.

Attributes:
    id: Unique group identifier
    findings: Findings in this group
    group_type: Type of correlation grouping
    root_cause: Identified root cause (if any)
    aggregate_severity: Combined severity
    aggregate_risk_score: Combined risk score
    affected_assets: List of affected asset IDs
    metadata: Additional group metadata

### Attributes

| Name | Type | Default |
|------|------|---------|
| `id` | `str` | - |
| `findings` | `list[Finding]` | - |
| `group_type` | `str` | - |
| `root_cause` | `str` | `` |
| `aggregate_severity` | `Severity` | `"Attribute(value=Name(id='Severity', ctx=Load()), attr='INFO', ctx=Load())"` |
| `aggregate_risk_score` | `float` | `0.0` |
| `affected_assets` | `list[str]` | `field(...)` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

### Properties

#### `finding_count(self) -> int`

Get number of findings in group.

**Returns:**

`int`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## CorrelationResult

**Tags:** dataclass

Result of correlation analysis.

Attributes:
    groups: Identified correlation groups
    uncorrelated_findings: Findings not in any group
    correlation_stats: Statistics about correlations
    analysis_time_ms: Time taken for analysis

### Attributes

| Name | Type | Default |
|------|------|---------|
| `groups` | `list[CorrelationGroup]` | `field(...)` |
| `uncorrelated_findings` | `list[Finding]` | `field(...)` |
| `correlation_stats` | `dict[(str, Any)]` | `field(...)` |
| `analysis_time_ms` | `int` | `0` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## FindingCorrelator

Correlates findings to identify patterns and relationships.

Analyzes findings to identify:
- Findings affecting the same asset
- Findings in the same network path
- Findings with common root causes
- Attack chains spanning multiple resources

Example:
    >>> correlator = FindingCorrelator()
    >>> result = correlator.correlate(findings, assets)
    >>> for group in result.groups:
    ...     print(f"Group {group.id}: {group.finding_count} findings")

### Methods

#### `__init__(self, time_window_hours: int = 24, min_group_size: int = 2, correlation_threshold: float = 0.5) -> None`

Initialize the correlator.

**Parameters:**

- `time_window_hours` (`int`) - default: `24` - Time window for temporal correlation
- `min_group_size` (`int`) - default: `2` - Minimum findings to form a group
- `correlation_threshold` (`float`) - default: `0.5` - Minimum score for correlation

**Returns:**

`None`

#### `correlate(self, findings: FindingCollection | list[Finding], assets: AssetCollection | list[Asset] | None) -> CorrelationResult`

Correlate findings and identify groups.

**Parameters:**

- `findings` (`FindingCollection | list[Finding]`) - Findings to correlate
- `assets` (`AssetCollection | list[Asset] | None`) - Optional assets for enriched correlation

**Returns:**

`CorrelationResult` - CorrelationResult with groups and statistics

#### `find_related(self, finding: Finding, all_findings: list[Finding]) -> list[CorrelatedFinding]`

Find findings related to a specific finding.

**Parameters:**

- `finding` (`Finding`) - Finding to find relations for
- `all_findings` (`list[Finding]`) - Pool of findings to search

**Returns:**

`list[CorrelatedFinding]` - List of correlated findings with scores
