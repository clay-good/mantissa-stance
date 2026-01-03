# stance.reporting.trends

Trend Analysis for Mantissa Stance.

Provides comprehensive trend analysis capabilities for tracking security
posture changes over time, including findings trends, compliance trends,
and statistical metrics.

## Contents

### Classes

- [TrendDirection](#trenddirection)
- [TrendPeriod](#trendperiod)
- [TrendMetrics](#trendmetrics)
- [SeverityTrend](#severitytrend)
- [ComplianceTrend](#compliancetrend)
- [TrendReport](#trendreport)
- [TrendAnalyzer](#trendanalyzer)

## TrendDirection

**Inherits from:** Enum

Direction of a trend.

## TrendPeriod

**Inherits from:** Enum

Time periods for trend analysis.

## TrendMetrics

**Tags:** dataclass

Statistical metrics for trend analysis.

Attributes:
    current_value: Most recent value
    previous_value: Value from previous period
    average: Average value over the period
    min_value: Minimum value observed
    max_value: Maximum value observed
    change: Absolute change from previous
    change_percent: Percentage change from previous
    direction: Trend direction
    data_points: Number of data points analyzed
    velocity: Rate of change per day

### Attributes

| Name | Type | Default |
|------|------|---------|
| `current_value` | `float` | - |
| `previous_value` | `float` | - |
| `average` | `float` | - |
| `min_value` | `float` | - |
| `max_value` | `float` | - |
| `change` | `float` | - |
| `change_percent` | `float` | - |
| `direction` | `TrendDirection` | - |
| `data_points` | `int` | - |
| `velocity` | `float` | `0.0` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## SeverityTrend

**Tags:** dataclass

Trend data for a specific severity level.

Attributes:
    severity: The severity level
    metrics: Trend metrics for this severity
    history: Historical data points

### Attributes

| Name | Type | Default |
|------|------|---------|
| `severity` | `str` | - |
| `metrics` | `TrendMetrics` | - |
| `history` | `list[dict[(str, Any)]]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## ComplianceTrend

**Tags:** dataclass

Trend data for compliance scores.

Attributes:
    framework: Compliance framework name
    metrics: Trend metrics for this framework
    current_score: Current compliance score (0-100)
    target_score: Target compliance score
    gap: Gap between current and target
    history: Historical score data

### Attributes

| Name | Type | Default |
|------|------|---------|
| `framework` | `str` | - |
| `metrics` | `TrendMetrics` | - |
| `current_score` | `float` | - |
| `target_score` | `float` | `100.0` |
| `gap` | `float` | `0.0` |
| `history` | `list[dict[(str, Any)]]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## TrendReport

**Tags:** dataclass

Complete trend analysis report.

Attributes:
    report_id: Unique report identifier
    generated_at: When the report was generated
    period: Time period analyzed
    days_analyzed: Number of days in the analysis
    total_findings: Trend for total findings count
    severity_trends: Trends by severity level
    compliance_trends: Trends by compliance framework
    assets_trend: Trend for assets count
    scan_frequency: Average scans per day
    mean_time_to_remediate: Average time to resolve findings
    risk_score_trend: Overall risk score trend
    summary: Summary insights
    recommendations: Recommendations based on trends

### Attributes

| Name | Type | Default |
|------|------|---------|
| `report_id` | `str` | - |
| `generated_at` | `datetime` | - |
| `period` | `TrendPeriod` | - |
| `days_analyzed` | `int` | - |
| `total_findings` | `TrendMetrics` | - |
| `severity_trends` | `dict[(str, SeverityTrend)]` | `field(...)` |
| `compliance_trends` | `dict[(str, ComplianceTrend)]` | `field(...)` |
| `assets_trend` | `TrendMetrics | None` | - |
| `scan_frequency` | `float` | `0.0` |
| `mean_time_to_remediate` | `float | None` | - |
| `risk_score_trend` | `TrendMetrics | None` | - |
| `summary` | `dict[(str, Any)]` | `field(...)` |
| `recommendations` | `list[str]` | `field(...)` |

### Properties

#### `overall_direction(self) -> TrendDirection`

Get overall trend direction based on total findings.

**Returns:**

`TrendDirection`

#### `is_improving(self) -> bool`

Check if overall trend is improving.

**Returns:**

`bool`

#### `critical_severity_change(self) -> float`

Get change in critical findings.

**Returns:**

`float`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## TrendAnalyzer

Analyzes security posture trends over time.

Provides comprehensive trend analysis including findings trends,
severity breakdowns, compliance tracking, and recommendations.

### Properties

#### `history_manager(self) -> ScanHistoryManager`

Get the history manager.

**Returns:**

`ScanHistoryManager`

### Methods

#### `__init__(self, history_manager: ScanHistoryManager | None, storage_path: str = ~/.stance/history)`

Initialize the trend analyzer.

**Parameters:**

- `history_manager` (`ScanHistoryManager | None`) - Optional history manager instance
- `storage_path` (`str`) - default: `~/.stance/history` - Path for history storage if no manager provided

#### `analyze(self, config_name: str = default, days: int = 30, period: TrendPeriod = "Attribute(value=Name(id='TrendPeriod', ctx=Load()), attr='DAILY', ctx=Load())", compliance_scores: dict[(str, list[dict[(str, Any)]])] | None) -> TrendReport`

Perform trend analysis.

**Parameters:**

- `config_name` (`str`) - default: `default` - Configuration to analyze
- `days` (`int`) - default: `30` - Number of days to include in analysis
- `period` (`TrendPeriod`) - default: `"Attribute(value=Name(id='TrendPeriod', ctx=Load()), attr='DAILY', ctx=Load())"` - Time period granularity
- `compliance_scores` (`dict[(str, list[dict[(str, Any)]])] | None`) - Historical compliance scores by framework

**Returns:**

`TrendReport` - TrendReport with complete analysis

#### `analyze_from_entries(self, entries: list[ScanHistoryEntry], period: TrendPeriod = "Attribute(value=Name(id='TrendPeriod', ctx=Load()), attr='DAILY', ctx=Load())") -> TrendReport`

Perform trend analysis from a list of entries.

**Parameters:**

- `entries` (`list[ScanHistoryEntry]`) - List of scan history entries
- `period` (`TrendPeriod`) - default: `"Attribute(value=Name(id='TrendPeriod', ctx=Load()), attr='DAILY', ctx=Load())"` - Time period granularity

**Returns:**

`TrendReport` - TrendReport with complete analysis

#### `get_findings_velocity(self, config_name: str = default, days: int = 7) -> dict[(str, float)]`

Calculate the velocity of findings changes.  Velocity is the rate of change per day.

**Parameters:**

- `config_name` (`str`) - default: `default` - Configuration to analyze
- `days` (`int`) - default: `7` - Number of days to analyze

**Returns:**

`dict[(str, float)]` - Dictionary with velocity for total and each severity

#### `get_improvement_rate(self, config_name: str = default, days: int = 30) -> float`

Calculate the improvement rate.  Positive values indicate improvement (decreasing findings). Negative values indicate regression (increasing findings).

**Parameters:**

- `config_name` (`str`) - default: `default` - Configuration to analyze
- `days` (`int`) - default: `30` - Number of days to analyze

**Returns:**

`float` - Improvement rate as a percentage

#### `compare_periods(self, config_name: str = default, current_days: int = 7, previous_days: int = 7) -> dict[(str, Any)]`

Compare two time periods.

**Parameters:**

- `config_name` (`str`) - default: `default` - Configuration to analyze
- `current_days` (`int`) - default: `7` - Days in current period
- `previous_days` (`int`) - default: `7` - Days in previous period

**Returns:**

`dict[(str, Any)]` - Comparison of the two periods

#### `forecast(self, config_name: str = default, days_history: int = 30, days_forecast: int = 7) -> dict[(str, Any)]`

Forecast future findings based on historical trend.  Uses linear regression on historical data to project future values.

**Parameters:**

- `config_name` (`str`) - default: `default` - Configuration to analyze
- `days_history` (`int`) - default: `30` - Days of history to use for forecast
- `days_forecast` (`int`) - default: `7` - Days to forecast ahead

**Returns:**

`dict[(str, Any)]` - Forecast data including projected values
