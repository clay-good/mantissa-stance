# stance.observability.tracing

Distributed tracing for Mantissa Stance.

Provides trace context propagation and span recording for
tracking request flows across collectors, evaluators, and APIs.
Supports multiple backends including in-memory, AWS X-Ray,
Google Cloud Trace, and Azure Application Insights.

## Contents

### Classes

- [SpanStatus](#spanstatus)
- [SpanContext](#spancontext)
- [Span](#span)
- [TracingBackend](#tracingbackend)
- [InMemoryTracingBackend](#inmemorytracingbackend)
- [XRayTracingBackend](#xraytracingbackend)
- [CloudTraceBackend](#cloudtracebackend)
- [ApplicationInsightsBackend](#applicationinsightsbackend)
- [StanceTracer](#stancetracer)

### Functions

- [get_tracer](#get_tracer)
- [configure_tracing](#configure_tracing)

## SpanStatus

**Inherits from:** Enum

Status of a span.

## SpanContext

**Tags:** dataclass

Context for trace propagation.

Contains trace and span IDs for correlating spans
across service boundaries.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `trace_id` | `str` | - |
| `span_id` | `str` | - |
| `parent_span_id` | `str | None` | - |
| `sampled` | `bool` | `True` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary for serialization.

**Returns:**

`dict[(str, Any)]`

#### `new_child(self) -> SpanContext`

Create a child span context.

**Returns:**

`SpanContext`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> SpanContext`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)

**Returns:**

`SpanContext`

#### `new_root(cls, sampled: bool = True) -> SpanContext`

**Decorators:** @classmethod

Create a new root span context.

**Parameters:**

- `sampled` (`bool`) - default: `True`

**Returns:**

`SpanContext`

### Static Methods

#### `_generate_trace_id() -> str`

**Decorators:** @staticmethod

Generate a unique trace ID.

**Returns:**

`str`

#### `_generate_span_id() -> str`

**Decorators:** @staticmethod

Generate a unique span ID.

**Returns:**

`str`

## Span

**Tags:** dataclass

A single span in a trace.

Represents a unit of work with timing, status, and metadata.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `name` | `str` | - |
| `context` | `SpanContext` | - |
| `start_time` | `datetime` | `field(...)` |
| `end_time` | `datetime | None` | - |
| `status` | `SpanStatus` | `"Attribute(value=Name(id='SpanStatus', ctx=Load()), attr='OK', ctx=Load())"` |
| `attributes` | `dict[(str, Any)]` | `field(...)` |
| `events` | `list[dict[(str, Any)]]` | `field(...)` |
| `error_message` | `str | None` | - |

### Properties

#### `duration_ms(self) -> float | None`

Get span duration in milliseconds.

**Returns:**

`float | None`

### Methods

#### `set_attribute(self, key: str, value: Any) -> None`

Set a span attribute.

**Parameters:**

- `key` (`str`)
- `value` (`Any`)

**Returns:**

`None`

#### `add_event(self, name: str, attributes: dict[(str, Any)] | None) -> None`

Add an event to the span.

**Parameters:**

- `name` (`str`)
- `attributes` (`dict[(str, Any)] | None`)

**Returns:**

`None`

#### `set_error(self, error: str | Exception) -> None`

Mark the span as errored.

**Parameters:**

- `error` (`str | Exception`)

**Returns:**

`None`

#### `end(self) -> None`

End the span.

**Returns:**

`None`

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## TracingBackend

**Inherits from:** ABC

Abstract base class for tracing backends.

### Methods

#### `record_span(self, span: Span) -> None`

**Decorators:** @abstractmethod

Record a completed span.

**Parameters:**

- `span` (`Span`)

**Returns:**

`None`

#### `flush(self) -> None`

**Decorators:** @abstractmethod

Flush any buffered spans.

**Returns:**

`None`

## InMemoryTracingBackend

**Inherits from:** TracingBackend

In-memory tracing backend for testing and local development.

Stores spans in memory and provides query methods.

### Methods

#### `__init__(self, max_size: int = 1000)`

Initialize in-memory backend.

**Parameters:**

- `max_size` (`int`) - default: `1000` - Maximum number of spans to store

#### `record_span(self, span: Span) -> None`

Record a span.

**Parameters:**

- `span` (`Span`)

**Returns:**

`None`

#### `flush(self) -> None`

No-op for in-memory backend.

**Returns:**

`None`

#### `get_trace(self, trace_id: str) -> list[Span]`

Get all spans for a trace.

**Parameters:**

- `trace_id` (`str`)

**Returns:**

`list[Span]`

#### `get_spans(self, name: str | None, since: datetime | None) -> list[Span]`

Query stored spans.

**Parameters:**

- `name` (`str | None`) - Filter by span name
- `since` (`datetime | None`) - Filter by start time

**Returns:**

`list[Span]` - List of matching spans

#### `clear(self) -> None`

Clear all stored spans.

**Returns:**

`None`

## XRayTracingBackend

**Inherits from:** TracingBackend

AWS X-Ray tracing backend.

Sends traces to X-Ray for distributed tracing visualization.

### Methods

#### `__init__(self, region: str = us-east-1, service_name: str = mantissa-stance, buffer_size: int = 10)`

Initialize X-Ray backend.

**Parameters:**

- `region` (`str`) - default: `us-east-1` - AWS region
- `service_name` (`str`) - default: `mantissa-stance` - Service name for X-Ray
- `buffer_size` (`int`) - default: `10` - Number of spans to buffer before sending

#### `record_span(self, span: Span) -> None`

Record a span.

**Parameters:**

- `span` (`Span`)

**Returns:**

`None`

#### `flush(self) -> None`

Send buffered spans to X-Ray.

**Returns:**

`None`

## CloudTraceBackend

**Inherits from:** TracingBackend

Google Cloud Trace backend.

Sends traces to Cloud Trace for distributed tracing visualization.

### Methods

#### `__init__(self, project_id: str, service_name: str = mantissa-stance, buffer_size: int = 10)`

Initialize Cloud Trace backend.

**Parameters:**

- `project_id` (`str`) - GCP project ID
- `service_name` (`str`) - default: `mantissa-stance` - Service name for traces
- `buffer_size` (`int`) - default: `10` - Number of spans to buffer before sending

#### `record_span(self, span: Span) -> None`

Record a span.

**Parameters:**

- `span` (`Span`)

**Returns:**

`None`

#### `flush(self) -> None`

Send buffered spans to Cloud Trace.

**Returns:**

`None`

## ApplicationInsightsBackend

**Inherits from:** TracingBackend

Azure Application Insights tracing backend.

Sends traces to Application Insights for distributed tracing.

### Methods

#### `__init__(self, connection_string: str | None, service_name: str = mantissa-stance, buffer_size: int = 10)`

Initialize Application Insights backend.

**Parameters:**

- `connection_string` (`str | None`) - Application Insights connection string
- `service_name` (`str`) - default: `mantissa-stance` - Service name for traces
- `buffer_size` (`int`) - default: `10` - Number of spans to buffer before sending

#### `record_span(self, span: Span) -> None`

Record a span.

**Parameters:**

- `span` (`Span`)

**Returns:**

`None`

#### `flush(self) -> None`

Send buffered spans to Application Insights.

**Returns:**

`None`

## StanceTracer

High-level tracing interface for Stance.

Provides convenient methods for creating and managing spans.

### Properties

#### `current_context(self) -> SpanContext | None`

Get the current span context.

**Returns:**

`SpanContext | None`

### Methods

#### `__init__(self, backend: TracingBackend | None)`

Initialize tracer.

**Parameters:**

- `backend` (`TracingBackend | None`) - Tracing backend (default: InMemoryTracingBackend)

#### `start_span(self, name: str, parent: SpanContext | None, attributes: dict[(str, Any)] | None) -> Span`

Start a new span.

**Parameters:**

- `name` (`str`) - Span name
- `parent` (`SpanContext | None`) - Parent span context (uses current if not provided)
- `attributes` (`dict[(str, Any)] | None`) - Initial attributes

**Returns:**

`Span` - New span

#### `end_span(self, span: Span) -> None`

End a span and record it.

**Parameters:**

- `span` (`Span`) - The span to end

**Returns:**

`None`

#### `span(self, name: str, parent: SpanContext | None, attributes: dict[(str, Any)] | None) -> Iterator[Span]`

**Decorators:** @contextmanager

Context manager for creating spans.

**Parameters:**

- `name` (`str`) - Span name
- `parent` (`SpanContext | None`) - Parent span context
- `attributes` (`dict[(str, Any)] | None`) - Initial attributes

**Returns:**

`Iterator[Span]`

#### `trace_scan(self, scan_id: str, config_name: str = default) -> Iterator[Span]`

Context manager for tracing a scan.

**Parameters:**

- `scan_id` (`str`) - Scan identifier
- `config_name` (`str`) - default: `default` - Configuration name

**Returns:**

`Iterator[Span]`

#### `trace_collector(self, collector_name: str, region: str = ) -> Iterator[Span]`

Context manager for tracing a collector.

**Parameters:**

- `collector_name` (`str`) - Name of the collector
- `region` (`str`) - default: `` - Cloud region

**Returns:**

`Iterator[Span]`

#### `trace_policy_evaluation(self, policy_id: str, asset_count: int = 0) -> Iterator[Span]`

Context manager for tracing policy evaluation.

**Parameters:**

- `policy_id` (`str`) - Policy identifier
- `asset_count` (`int`) - default: `0` - Number of assets being evaluated

**Returns:**

`Iterator[Span]`

#### `trace_api_request(self, method: str, endpoint: str) -> Iterator[Span]`

Context manager for tracing an API request.

**Parameters:**

- `method` (`str`) - HTTP method
- `endpoint` (`str`) - API endpoint

**Returns:**

`Iterator[Span]`

#### `trace_query(self, query_type: str, backend: str = unknown) -> Iterator[Span]`

Context manager for tracing a query.

**Parameters:**

- `query_type` (`str`) - Type of query (sql, natural_language)
- `backend` (`str`) - default: `unknown` - Query backend (athena, bigquery, etc.)

**Returns:**

`Iterator[Span]`

#### `flush(self) -> None`

Flush any buffered spans.

**Returns:**

`None`

### `get_tracer() -> StanceTracer`

Get the global tracer instance.

**Returns:**

`StanceTracer` - StanceTracer instance

### `configure_tracing(backend: TracingBackend) -> StanceTracer`

Configure the global tracer instance.

**Parameters:**

- `backend` (`TracingBackend`) - Tracing backend to use

**Returns:**

`StanceTracer` - Configured StanceTracer instance
