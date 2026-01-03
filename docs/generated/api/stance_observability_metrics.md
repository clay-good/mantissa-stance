# stance.observability.metrics

Metrics collection for Mantissa Stance.

Provides metrics collection and reporting for monitoring
scan performance, finding trends, and system health.

## Contents

### Classes

- [MetricType](#metrictype)
- [MetricValue](#metricvalue)
- [MetricsBackend](#metricsbackend)
- [InMemoryMetricsBackend](#inmemorymetricsbackend)
- [CloudWatchMetricsBackend](#cloudwatchmetricsbackend)
- [StanceMetrics](#stancemetrics)

### Functions

- [get_metrics](#get_metrics)
- [configure_metrics](#configure_metrics)

## MetricType

**Inherits from:** Enum

Types of metrics.

## MetricValue

**Tags:** dataclass

A single metric value.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `name` | `str` | - |
| `value` | `float` | - |
| `metric_type` | `MetricType` | - |
| `timestamp` | `datetime` | `field(...)` |
| `tags` | `dict[(str, str)]` | `field(...)` |
| `unit` | `str` | `` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## MetricsBackend

**Inherits from:** ABC

Abstract base class for metrics backends.

### Methods

#### `record(self, metric: MetricValue) -> None`

**Decorators:** @abstractmethod

Record a metric value.

**Parameters:**

- `metric` (`MetricValue`)

**Returns:**

`None`

#### `flush(self) -> None`

**Decorators:** @abstractmethod

Flush any buffered metrics.

**Returns:**

`None`

## InMemoryMetricsBackend

**Inherits from:** MetricsBackend

In-memory metrics backend for testing and local development.

Stores metrics in memory and provides query methods.

### Methods

#### `__init__(self, max_size: int = 10000)`

Initialize in-memory backend.

**Parameters:**

- `max_size` (`int`) - default: `10000` - Maximum number of metrics to store

#### `record(self, metric: MetricValue) -> None`

Record a metric value.

**Parameters:**

- `metric` (`MetricValue`)

**Returns:**

`None`

#### `flush(self) -> None`

No-op for in-memory backend.

**Returns:**

`None`

#### `get_metrics(self, name: str | None, since: datetime | None) -> list[MetricValue]`

Query stored metrics.

**Parameters:**

- `name` (`str | None`) - Filter by metric name
- `since` (`datetime | None`) - Filter by timestamp

**Returns:**

`list[MetricValue]` - List of matching metrics

#### `clear(self) -> None`

Clear all stored metrics.

**Returns:**

`None`

## CloudWatchMetricsBackend

**Inherits from:** MetricsBackend

AWS CloudWatch metrics backend.

Sends metrics to CloudWatch for monitoring and alerting.

### Methods

#### `__init__(self, namespace: str = MantissaStance, region: str = us-east-1, buffer_size: int = 20)`

Initialize CloudWatch backend.

**Parameters:**

- `namespace` (`str`) - default: `MantissaStance` - CloudWatch namespace
- `region` (`str`) - default: `us-east-1` - AWS region
- `buffer_size` (`int`) - default: `20` - Number of metrics to buffer before sending

#### `record(self, metric: MetricValue) -> None`

Record a metric value.

**Parameters:**

- `metric` (`MetricValue`)

**Returns:**

`None`

#### `flush(self) -> None`

Send buffered metrics to CloudWatch.

**Returns:**

`None`

## StanceMetrics

High-level metrics collection for Stance.

Provides convenient methods for recording common metrics.

### Methods

#### `__init__(self, backend: MetricsBackend | None)`

Initialize metrics collector.

**Parameters:**

- `backend` (`MetricsBackend | None`) - Metrics backend (default: InMemoryMetricsBackend)

#### `set_default_tags(self, **tags: str) -> None`

Set default tags for all metrics.

**Parameters:**

- `**tags` (`str`)

**Returns:**

`None`

#### `counter(self, name: str, value: float = 1, **tags: str) -> None`

Increment a counter.

**Parameters:**

- `name` (`str`) - Metric name
- `value` (`float`) - default: `1` - Increment value (default: 1) **tags: Additional tags
- `**tags` (`str`)

**Returns:**

`None`

#### `gauge(self, name: str, value: float, unit: str = , **tags: str) -> None`

Set a gauge value.

**Parameters:**

- `name` (`str`) - Metric name
- `value` (`float`) - Current value
- `unit` (`str`) - default: `` - Unit of measurement **tags: Additional tags
- `**tags` (`str`)

**Returns:**

`None`

#### `timing(self, name: str, duration_seconds: float, **tags: str) -> None`

Record a timing measurement.

**Parameters:**

- `name` (`str`) - Metric name
- `duration_seconds` (`float`) - Duration in seconds **tags: Additional tags
- `**tags` (`str`)

**Returns:**

`None`

#### `timer(self, name: str, **tags: str) -> Iterator[None]`

**Decorators:** @contextmanager

Context manager for timing a block of code.

**Parameters:**

- `name` (`str`) - Metric name **tags: Additional tags
- `**tags` (`str`)

**Returns:**

`Iterator[None]`

#### `scan_started(self, scan_id: str, config_name: str = default) -> None`

Record scan start.

**Parameters:**

- `scan_id` (`str`)
- `config_name` (`str`) - default: `default`

**Returns:**

`None`

#### `scan_completed(self, scan_id: str, duration_seconds: float, asset_count: int, finding_count: int) -> None`

Record scan completion.

**Parameters:**

- `scan_id` (`str`)
- `duration_seconds` (`float`)
- `asset_count` (`int`)
- `finding_count` (`int`)

**Returns:**

`None`

#### `scan_failed(self, scan_id: str, error_type: str = unknown) -> None`

Record scan failure.

**Parameters:**

- `scan_id` (`str`)
- `error_type` (`str`) - default: `unknown`

**Returns:**

`None`

#### `collector_started(self, collector_name: str, region: str = ) -> None`

Record collector start.

**Parameters:**

- `collector_name` (`str`)
- `region` (`str`) - default: ``

**Returns:**

`None`

#### `collector_completed(self, collector_name: str, duration_seconds: float, asset_count: int, region: str = ) -> None`

Record collector completion.

**Parameters:**

- `collector_name` (`str`)
- `duration_seconds` (`float`)
- `asset_count` (`int`)
- `region` (`str`) - default: ``

**Returns:**

`None`

#### `collector_failed(self, collector_name: str, error_type: str = unknown, region: str = ) -> None`

Record collector failure.

**Parameters:**

- `collector_name` (`str`)
- `error_type` (`str`) - default: `unknown`
- `region` (`str`) - default: ``

**Returns:**

`None`

#### `finding_generated(self, severity: str, rule_id: str) -> None`

Record finding generation.

**Parameters:**

- `severity` (`str`)
- `rule_id` (`str`)

**Returns:**

`None`

#### `findings_by_severity(self, counts: dict[(str, int)]) -> None`

Record finding counts by severity.

**Parameters:**

- `counts` (`dict[(str, int)]`)

**Returns:**

`None`

#### `policy_evaluated(self, policy_id: str, duration_seconds: float) -> None`

Record policy evaluation.

**Parameters:**

- `policy_id` (`str`)
- `duration_seconds` (`float`)

**Returns:**

`None`

#### `policies_loaded(self, count: int) -> None`

Record number of policies loaded.

**Parameters:**

- `count` (`int`)

**Returns:**

`None`

#### `api_request(self, endpoint: str, method: str, status_code: int, duration_seconds: float) -> None`

Record API request.

**Parameters:**

- `endpoint` (`str`)
- `method` (`str`)
- `status_code` (`int`)
- `duration_seconds` (`float`)

**Returns:**

`None`

#### `flush(self) -> None`

Flush any buffered metrics.

**Returns:**

`None`

### `get_metrics() -> StanceMetrics`

Get the global metrics instance.

**Returns:**

`StanceMetrics` - StanceMetrics instance

### `configure_metrics(backend: MetricsBackend) -> StanceMetrics`

Configure the global metrics instance.

**Parameters:**

- `backend` (`MetricsBackend`) - Metrics backend to use

**Returns:**

`StanceMetrics` - Configured StanceMetrics instance
