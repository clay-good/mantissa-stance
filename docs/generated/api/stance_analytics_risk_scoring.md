# stance.analytics.risk_scoring

Risk Scoring for Mantissa Stance.

Calculates risk scores for assets based on exposure, findings, compliance
status, and relationships within the asset graph.

## Contents

### Classes

- [RiskFactors](#riskfactors)
- [RiskScore](#riskscore)
- [RiskTrend](#risktrend)
- [RiskScorer](#riskscorer)

## RiskFactors

**Tags:** dataclass

Individual risk factors that contribute to an asset's risk score.

Attributes:
    exposure_score: Risk from network exposure (0-100)
    finding_score: Risk from security findings (0-100)
    compliance_score: Risk from compliance violations (0-100)
    relationship_score: Risk from connected assets (0-100)
    age_score: Risk from resource age/staleness (0-100)

### Attributes

| Name | Type | Default |
|------|------|---------|
| `exposure_score` | `float` | `0.0` |
| `finding_score` | `float` | `0.0` |
| `compliance_score` | `float` | `0.0` |
| `relationship_score` | `float` | `0.0` |
| `age_score` | `float` | `0.0` |

### Methods

#### `to_dict(self) -> dict[(str, float)]`

Convert to dictionary.

**Returns:**

`dict[(str, float)]`

## RiskScore

**Tags:** dataclass

Complete risk assessment for an asset.

Attributes:
    asset_id: ID of the assessed asset
    overall_score: Combined risk score (0-100)
    risk_level: Risk level category
    factors: Individual risk factors
    top_risks: List of top risk contributors
    recommendations: Suggested risk mitigation actions
    last_updated: When the score was calculated

### Attributes

| Name | Type | Default |
|------|------|---------|
| `asset_id` | `str` | - |
| `overall_score` | `float` | - |
| `risk_level` | `str` | - |
| `factors` | `RiskFactors` | - |
| `top_risks` | `list[str]` | `field(...)` |
| `recommendations` | `list[str]` | `field(...)` |
| `last_updated` | `datetime` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## RiskTrend

**Tags:** dataclass

Risk score trend over time for an asset.

Attributes:
    asset_id: ID of the asset
    scores: List of (timestamp, score) tuples
    trend_direction: 'improving', 'worsening', or 'stable'
    change_percentage: Percentage change from oldest to newest

### Attributes

| Name | Type | Default |
|------|------|---------|
| `asset_id` | `str` | - |
| `scores` | `list[tuple[(datetime, float)]]` | `field(...)` |
| `trend_direction` | `str` | `stable` |
| `change_percentage` | `float` | `0.0` |

### Methods

#### `add_score(self, timestamp: datetime, score: float) -> None`

Add a new score to the trend.

**Parameters:**

- `timestamp` (`datetime`)
- `score` (`float`)

**Returns:**

`None`

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## RiskScorer

Calculates risk scores for cloud assets.

Considers multiple factors including network exposure, security findings,
compliance status, and relationships with other assets.

### Methods

#### `__init__(self, graph: AssetGraph | None, findings: FindingCollection | None) -> None`

Initialize the risk scorer.

**Parameters:**

- `graph` (`AssetGraph | None`) - Optional asset graph for relationship analysis
- `findings` (`FindingCollection | None`) - Optional findings collection

**Returns:**

`None`

#### `score_asset(self, asset: Asset) -> RiskScore`

Calculate the risk score for a single asset.

**Parameters:**

- `asset` (`Asset`) - Asset to score

**Returns:**

`RiskScore` - RiskScore with detailed breakdown

#### `score_collection(self, assets: AssetCollection) -> list[RiskScore]`

Calculate risk scores for all assets in a collection.

**Parameters:**

- `assets` (`AssetCollection`) - Collection of assets to score

**Returns:**

`list[RiskScore]` - List of RiskScores sorted by overall score (highest first)

#### `get_trend(self, asset_id: str) -> RiskTrend | None`

Get the risk trend for an asset.

**Parameters:**

- `asset_id` (`str`)

**Returns:**

`RiskTrend | None`

#### `get_high_risk_assets(self, assets: AssetCollection, threshold: float = 70.0) -> list[RiskScore]`

Get assets with risk scores above a threshold.

**Parameters:**

- `assets` (`AssetCollection`) - Collection of assets to check
- `threshold` (`float`) - default: `70.0` - Minimum risk score to include

**Returns:**

`list[RiskScore]` - List of high-risk RiskScores

#### `aggregate_risk(self, assets: AssetCollection) -> dict[(str, Any)]`

Calculate aggregate risk metrics for an asset collection.

**Parameters:**

- `assets` (`AssetCollection`) - Collection of assets

**Returns:**

`dict[(str, Any)]` - Dictionary with aggregate risk metrics
