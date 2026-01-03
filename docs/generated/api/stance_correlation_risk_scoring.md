# stance.correlation.risk_scoring

Risk scoring for Mantissa Stance.

Provides risk score calculation based on findings,
asset exposure, compliance status, and trends.

## Contents

### Classes

- [RiskLevel](#risklevel)
- [RiskFactor](#riskfactor)
- [AssetRiskScore](#assetriskscore)
- [RiskTrend](#risktrend)
- [RiskScoringResult](#riskscoringresult)
- [RiskScorer](#riskscorer)

## RiskLevel

**Inherits from:** Enum

Risk level classification.

## RiskFactor

**Tags:** dataclass

Individual risk factor contributing to overall score.

Attributes:
    name: Factor name
    category: Factor category (exposure, findings, compliance, etc.)
    weight: Weight multiplier for this factor
    score: Raw score before weighting (0-100)
    weighted_score: Score after applying weight
    details: Additional details about the factor

### Attributes

| Name | Type | Default |
|------|------|---------|
| `name` | `str` | - |
| `category` | `str` | - |
| `weight` | `float` | - |
| `score` | `float` | - |
| `weighted_score` | `float` | `field(...)` |
| `details` | `dict[(str, Any)]` | `field(...)` |

## AssetRiskScore

**Tags:** dataclass

Risk score for a single asset.

Attributes:
    asset_id: Asset identifier
    asset_name: Human-readable asset name
    asset_type: Resource type
    cloud_provider: Cloud provider
    overall_score: Combined risk score (0-100)
    risk_level: Classified risk level
    factors: Individual risk factors
    finding_count: Number of open findings
    critical_findings: Count of critical findings
    high_findings: Count of high findings
    exposure_level: Network exposure classification
    compliance_gaps: List of compliance framework gaps
    calculated_at: Timestamp of calculation

### Attributes

| Name | Type | Default |
|------|------|---------|
| `asset_id` | `str` | - |
| `asset_name` | `str` | - |
| `asset_type` | `str` | - |
| `cloud_provider` | `str` | - |
| `overall_score` | `float` | - |
| `risk_level` | `RiskLevel` | - |
| `factors` | `list[RiskFactor]` | - |
| `finding_count` | `int` | - |
| `critical_findings` | `int` | - |
| `high_findings` | `int` | - |
| `exposure_level` | `str` | - |
| `compliance_gaps` | `list[str]` | - |
| `calculated_at` | `datetime` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary representation.

**Returns:**

`dict[(str, Any)]`

## RiskTrend

**Tags:** dataclass

Risk trend over time.

Attributes:
    period_start: Start of trend period
    period_end: End of trend period
    start_score: Score at period start
    end_score: Score at period end
    change: Absolute change in score
    change_percentage: Percentage change
    direction: Trend direction (improving, worsening, stable)
    data_points: Historical data points

### Attributes

| Name | Type | Default |
|------|------|---------|
| `period_start` | `datetime` | - |
| `period_end` | `datetime` | - |
| `start_score` | `float` | - |
| `end_score` | `float` | - |
| `change` | `float` | `field(...)` |
| `change_percentage` | `float` | `field(...)` |
| `direction` | `str` | `field(...)` |
| `data_points` | `list[tuple[(datetime, float)]]` | `field(...)` |

## RiskScoringResult

**Tags:** dataclass

Complete risk scoring result.

Attributes:
    asset_scores: Individual asset risk scores
    overall_score: Organization-wide risk score
    overall_risk_level: Organization risk level
    top_risks: Assets with highest risk
    risk_by_cloud: Risk breakdown by cloud provider
    risk_by_type: Risk breakdown by resource type
    trend: Risk trend if historical data available
    calculated_at: Timestamp of calculation

### Attributes

| Name | Type | Default |
|------|------|---------|
| `asset_scores` | `list[AssetRiskScore]` | - |
| `overall_score` | `float` | - |
| `overall_risk_level` | `RiskLevel` | - |
| `top_risks` | `list[AssetRiskScore]` | - |
| `risk_by_cloud` | `dict[(str, float)]` | - |
| `risk_by_type` | `dict[(str, float)]` | - |
| `trend` | `RiskTrend | None` | - |
| `calculated_at` | `datetime` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary representation.

**Returns:**

`dict[(str, Any)]`

## RiskScorer

Calculates risk scores for assets and organization.

Risk score components:
- Finding severity (40% weight)
- Network exposure (25% weight)
- Compliance gaps (20% weight)
- Asset criticality (15% weight)

Scores range from 0 (minimal risk) to 100 (critical risk).

### Methods

#### `__init__(self, weights: dict[(str, float)] | None, critical_resource_types: set[str] | None, historical_scores: list[tuple[(datetime, float)]] | None)`

Initialize risk scorer.

**Parameters:**

- `weights` (`dict[(str, float)] | None`) - Custom weights for risk factors
- `critical_resource_types` (`set[str] | None`) - Resource types considered critical
- `historical_scores` (`list[tuple[(datetime, float)]] | None`) - Historical scores for trend analysis

#### `calculate_scores(self, findings: FindingCollection | list[Finding], assets: AssetCollection | list[Asset], compliance_results: dict[(str, dict[(str, Any)])] | None) -> RiskScoringResult`

Calculate risk scores for all assets.

**Parameters:**

- `findings` (`FindingCollection | list[Finding]`) - Collection of findings
- `assets` (`AssetCollection | list[Asset]`) - Collection of assets
- `compliance_results` (`dict[(str, dict[(str, Any)])] | None`) - Optional compliance framework results

**Returns:**

`RiskScoringResult` - Complete risk scoring result

#### `get_risk_summary(self, result: RiskScoringResult) -> dict[(str, Any)]`

Generate executive risk summary.

**Parameters:**

- `result` (`RiskScoringResult`) - Risk scoring result

**Returns:**

`dict[(str, Any)]` - Summary dictionary suitable for reporting
