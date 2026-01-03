# stance.analytics.blast_radius

Blast Radius Calculator for Mantissa Stance.

Calculates the potential impact of security findings by analyzing
the scope of affected resources through asset relationships.

The blast radius helps prioritize findings based on their potential
downstream impact rather than just the severity of the finding itself.

Reference: Wiz/Orca blast radius analysis

## Contents

### Classes

- [ImpactCategory](#impactcategory)
- [AffectedResource](#affectedresource)
- [BlastRadius](#blastradius)
- [BlastRadiusCalculator](#blastradiuscalculator)

## ImpactCategory

**Inherits from:** Enum

Categories of potential impact from a security finding.

## AffectedResource

**Tags:** dataclass

A resource affected by a finding's blast radius.

Attributes:
    asset_id: ID of the affected asset
    asset_name: Human-readable name of the asset
    resource_type: Type of the resource
    impact_type: How the resource is impacted
    relationship_path: Path from the finding to this resource
    distance: Number of hops from the source finding
    impact_score: Calculated impact score for this resource

### Attributes

| Name | Type | Default |
|------|------|---------|
| `asset_id` | `str` | - |
| `asset_name` | `str` | - |
| `resource_type` | `str` | - |
| `impact_type` | `str` | - |
| `relationship_path` | `list[str]` | `field(...)` |
| `distance` | `int` | `0` |
| `impact_score` | `float` | `0.0` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## BlastRadius

**Tags:** dataclass

Represents the calculated blast radius of a security finding.

Attributes:
    finding_id: ID of the source finding
    finding_severity: Original severity of the finding
    source_asset_id: ID of the asset with the finding
    source_asset_name: Name of the asset with the finding
    directly_affected: Resources directly affected (distance=1)
    indirectly_affected: Resources indirectly affected (distance>1)
    impact_categories: Categories of impact detected
    data_exposure_risk: Data exposure risk assessment
    service_disruption_risk: Service disruption risk assessment
    compliance_implications: List of compliance implications
    total_affected_count: Total number of affected resources
    blast_radius_score: Overall blast radius score (0-100)
    adjusted_severity: Severity adjusted based on blast radius

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding_id` | `str` | - |
| `finding_severity` | `Severity` | - |
| `source_asset_id` | `str` | - |
| `source_asset_name` | `str` | - |
| `directly_affected` | `list[AffectedResource]` | `field(...)` |
| `indirectly_affected` | `list[AffectedResource]` | `field(...)` |
| `impact_categories` | `list[ImpactCategory]` | `field(...)` |
| `data_exposure_risk` | `str` | `none` |
| `service_disruption_risk` | `str` | `none` |
| `compliance_implications` | `list[str]` | `field(...)` |
| `total_affected_count` | `int` | `0` |
| `blast_radius_score` | `float` | `0.0` |
| `adjusted_severity` | `Severity` | `"Attribute(value=Name(id='Severity', ctx=Load()), attr='INFO', ctx=Load())"` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## BlastRadiusCalculator

Calculates the blast radius of security findings.

Analyzes asset relationships to determine the potential
downstream impact of security findings.

### Methods

#### `__init__(self, graph: AssetGraph, findings: FindingCollection | None, max_depth: int = 5) -> None`

Initialize the blast radius calculator.

**Parameters:**

- `graph` (`AssetGraph`) - Asset graph to analyze
- `findings` (`FindingCollection | None`) - Optional findings collection
- `max_depth` (`int`) - default: `5` - Maximum depth to traverse for blast radius

**Returns:**

`None`

#### `calculate(self, finding: Finding) -> BlastRadius`

Calculate the blast radius for a single finding.

**Parameters:**

- `finding` (`Finding`) - The finding to calculate blast radius for

**Returns:**

`BlastRadius` - BlastRadius object with impact analysis

#### `calculate_all(self) -> list[BlastRadius]`

Calculate blast radius for all findings.

**Returns:**

`list[BlastRadius]` - List of BlastRadius objects, sorted by blast_radius_score

#### `get_highest_impact_findings(self, limit: int = 10) -> list[BlastRadius]`

Get the findings with highest blast radius impact.

**Parameters:**

- `limit` (`int`) - default: `10` - Maximum number of findings to return

**Returns:**

`list[BlastRadius]` - List of BlastRadius objects with highest impact

#### `get_affected_by_category(self, category: ImpactCategory) -> list[BlastRadius]`

Get all blast radius results that have a specific impact category.

**Parameters:**

- `category` (`ImpactCategory`) - The impact category to filter by

**Returns:**

`list[BlastRadius]` - List of BlastRadius objects with the specified category
