# stance.web.aggregation

Data Aggregation API for Mantissa Stance Dashboard.

Provides aggregated data from the scheduling, scanning, and reporting
modules for use in the dashboard and API consumers.

## Contents

### Classes

- [SchedulerStatus](#schedulerstatus)
- [ScanHistorySummary](#scanhistorysummary)
- [TrendSummary](#trendsummary)
- [MultiAccountSummary](#multiaccountsummary)
- [DashboardAggregation](#dashboardaggregation)
- [DashboardAggregator](#dashboardaggregator)

### Functions

- [create_aggregator](#create_aggregator)

## SchedulerStatus

**Tags:** dataclass

Aggregated scheduler status.

Attributes:
    is_running: Whether scheduler is running
    total_jobs: Total number of jobs
    enabled_jobs: Number of enabled jobs
    pending_jobs: Jobs pending execution
    last_run: Most recent run time
    next_run: Next scheduled run time
    jobs: List of job details

### Attributes

| Name | Type | Default |
|------|------|---------|
| `is_running` | `bool` | `False` |
| `total_jobs` | `int` | `0` |
| `enabled_jobs` | `int` | `0` |
| `pending_jobs` | `int` | `0` |
| `last_run` | `datetime | None` | - |
| `next_run` | `datetime | None` | - |
| `jobs` | `list[dict[(str, Any)]]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## ScanHistorySummary

**Tags:** dataclass

Aggregated scan history summary.

Attributes:
    total_scans: Total number of scans
    scans_last_24h: Scans in last 24 hours
    scans_last_7d: Scans in last 7 days
    average_duration: Average scan duration in seconds
    average_findings: Average findings per scan
    latest_scan: Most recent scan details
    history: List of recent scan entries

### Attributes

| Name | Type | Default |
|------|------|---------|
| `total_scans` | `int` | `0` |
| `scans_last_24h` | `int` | `0` |
| `scans_last_7d` | `int` | `0` |
| `average_duration` | `float` | `0.0` |
| `average_findings` | `float` | `0.0` |
| `latest_scan` | `dict[(str, Any)] | None` | - |
| `history` | `list[dict[(str, Any)]]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## TrendSummary

**Tags:** dataclass

Aggregated trend summary.

Attributes:
    direction: Overall trend direction
    findings_change: Change in findings count
    findings_change_percent: Percentage change
    period_days: Days analyzed
    is_improving: Whether posture is improving
    severity_trends: Trend by severity
    recommendations: Trend-based recommendations

### Attributes

| Name | Type | Default |
|------|------|---------|
| `direction` | `str` | `stable` |
| `findings_change` | `int` | `0` |
| `findings_change_percent` | `float` | `0.0` |
| `period_days` | `int` | `7` |
| `is_improving` | `bool` | `False` |
| `severity_trends` | `dict[(str, dict[(str, Any)])]` | `field(...)` |
| `recommendations` | `list[str]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## MultiAccountSummary

**Tags:** dataclass

Aggregated multi-account summary.

Attributes:
    total_accounts: Total configured accounts
    accounts_by_provider: Count per cloud provider
    last_org_scan: Most recent organization scan
    accounts_with_findings: Number of accounts with findings
    total_findings: Total findings across accounts

### Attributes

| Name | Type | Default |
|------|------|---------|
| `total_accounts` | `int` | `0` |
| `accounts_by_provider` | `dict[(str, int)]` | `field(...)` |
| `last_org_scan` | `dict[(str, Any)] | None` | - |
| `accounts_with_findings` | `int` | `0` |
| `total_findings` | `int` | `0` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## DashboardAggregation

**Tags:** dataclass

Complete dashboard data aggregation.

Combines data from scheduler, history, trends, and multi-account
modules into a single response for dashboard consumption.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `generated_at` | `datetime` | `field(...)` |
| `scheduler` | `SchedulerStatus` | `field(...)` |
| `history` | `ScanHistorySummary` | `field(...)` |
| `trends` | `TrendSummary` | `field(...)` |
| `multi_account` | `MultiAccountSummary` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## DashboardAggregator

Aggregates data from multiple modules for dashboard display.

Provides a unified interface for gathering data from the scheduler,
history, trends, and multi-account modules.

### Methods

#### `__init__(self, scheduler: ScanScheduler | None, history_manager: ScanHistoryManager | None, trend_analyzer: TrendAnalyzer | None, multi_account_scanner: MultiAccountScanner | None)`

Initialize the aggregator.

**Parameters:**

- `scheduler` (`ScanScheduler | None`) - Optional ScanScheduler instance
- `history_manager` (`ScanHistoryManager | None`) - Optional ScanHistoryManager instance
- `trend_analyzer` (`TrendAnalyzer | None`) - Optional TrendAnalyzer instance
- `multi_account_scanner` (`MultiAccountScanner | None`) - Optional MultiAccountScanner instance

#### `set_scheduler(self, scheduler: ScanScheduler) -> None`

Set the scheduler instance.

**Parameters:**

- `scheduler` (`ScanScheduler`)

**Returns:**

`None`

#### `set_history_manager(self, manager: ScanHistoryManager) -> None`

Set the history manager instance.

**Parameters:**

- `manager` (`ScanHistoryManager`)

**Returns:**

`None`

#### `set_trend_analyzer(self, analyzer: TrendAnalyzer) -> None`

Set the trend analyzer instance.

**Parameters:**

- `analyzer` (`TrendAnalyzer`)

**Returns:**

`None`

#### `set_multi_account_scanner(self, scanner: MultiAccountScanner) -> None`

Set the multi-account scanner instance.

**Parameters:**

- `scanner` (`MultiAccountScanner`)

**Returns:**

`None`

#### `get_aggregation(self, config_name: str = default, trend_days: int = 7, history_limit: int = 10) -> DashboardAggregation`

Get complete dashboard aggregation.

**Parameters:**

- `config_name` (`str`) - default: `default` - Configuration name for filtering
- `trend_days` (`int`) - default: `7` - Days for trend analysis
- `history_limit` (`int`) - default: `10` - Maximum history entries

**Returns:**

`DashboardAggregation` - DashboardAggregation with all data

#### `get_scheduler_status(self) -> SchedulerStatus`

Get scheduler status.

**Returns:**

`SchedulerStatus`

#### `get_history_summary(self, config_name: str = default, limit: int = 10) -> ScanHistorySummary`

Get scan history summary.

**Parameters:**

- `config_name` (`str`) - default: `default`
- `limit` (`int`) - default: `10`

**Returns:**

`ScanHistorySummary`

#### `get_trend_summary(self, config_name: str = default, days: int = 7) -> TrendSummary`

Get trend summary.

**Parameters:**

- `config_name` (`str`) - default: `default`
- `days` (`int`) - default: `7`

**Returns:**

`TrendSummary`

#### `get_multi_account_summary(self) -> MultiAccountSummary`

Get multi-account summary.

**Returns:**

`MultiAccountSummary`

#### `get_forecast(self, config_name: str = default, history_days: int = 30, forecast_days: int = 7) -> dict[(str, Any)]`

Get findings forecast.

**Parameters:**

- `config_name` (`str`) - default: `default` - Configuration name
- `history_days` (`int`) - default: `30` - Days of history for model
- `forecast_days` (`int`) - default: `7` - Days to forecast

**Returns:**

`dict[(str, Any)]` - Forecast data

#### `get_period_comparison(self, config_name: str = default, current_days: int = 7, previous_days: int = 7) -> dict[(str, Any)]`

Get period comparison.

**Parameters:**

- `config_name` (`str`) - default: `default` - Configuration name
- `current_days` (`int`) - default: `7` - Days in current period
- `previous_days` (`int`) - default: `7` - Days in previous period

**Returns:**

`dict[(str, Any)]` - Comparison data

#### `get_velocity_metrics(self, config_name: str = default, days: int = 7) -> dict[(str, Any)]`

Get findings velocity metrics.

**Parameters:**

- `config_name` (`str`) - default: `default` - Configuration name
- `days` (`int`) - default: `7` - Days for velocity calculation

**Returns:**

`dict[(str, Any)]` - Velocity data by severity

### `create_aggregator(history_path: str = ~/.stance/history) -> DashboardAggregator`

Create a dashboard aggregator with default components.

**Parameters:**

- `history_path` (`str`) - default: `~/.stance/history` - Path for history storage

**Returns:**

`DashboardAggregator` - Configured DashboardAggregator
