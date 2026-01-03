"""
Unit tests for observability module.

Tests the logging, metrics, and tracing functionality for monitoring
scan performance and system health.
"""

from __future__ import annotations

import json
import logging
import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from stance.observability import (
    # Logging
    HumanReadableFormatter,
    StanceLogger,
    StructuredFormatter,
    configure_logging,
    get_logger,
    # Metrics
    CloudWatchMetricsBackend,
    InMemoryMetricsBackend,
    MetricsBackend,
    MetricType,
    MetricValue,
    StanceMetrics,
    configure_metrics,
    get_metrics,
    # Tracing
    ApplicationInsightsBackend,
    CloudTraceBackend,
    InMemoryTracingBackend,
    Span,
    SpanContext,
    SpanStatus,
    StanceTracer,
    TracingBackend,
    XRayTracingBackend,
    configure_tracing,
    get_tracer,
)


# ============================================================================
# MetricType Tests
# ============================================================================


class TestMetricType:
    """Tests for MetricType enum."""

    def test_metric_type_counter(self) -> None:
        """Test COUNTER metric type."""
        assert MetricType.COUNTER.value == "counter"

    def test_metric_type_gauge(self) -> None:
        """Test GAUGE metric type."""
        assert MetricType.GAUGE.value == "gauge"

    def test_metric_type_histogram(self) -> None:
        """Test HISTOGRAM metric type."""
        assert MetricType.HISTOGRAM.value == "histogram"

    def test_metric_type_timer(self) -> None:
        """Test TIMER metric type."""
        assert MetricType.TIMER.value == "timer"


# ============================================================================
# MetricValue Tests
# ============================================================================


class TestMetricValue:
    """Tests for MetricValue dataclass."""

    def test_metric_value_creation(self) -> None:
        """Test MetricValue can be created."""
        metric = MetricValue(
            name="test.metric",
            value=42.0,
            metric_type=MetricType.GAUGE,
        )

        assert metric.name == "test.metric"
        assert metric.value == 42.0
        assert metric.metric_type == MetricType.GAUGE
        assert metric.tags == {}
        assert metric.unit == ""

    def test_metric_value_with_all_fields(self) -> None:
        """Test MetricValue with all fields populated."""
        timestamp = datetime.utcnow()
        metric = MetricValue(
            name="findings.count",
            value=100.0,
            metric_type=MetricType.COUNTER,
            timestamp=timestamp,
            tags={"severity": "critical", "cloud": "aws"},
            unit="count",
        )

        assert metric.name == "findings.count"
        assert metric.tags["severity"] == "critical"
        assert metric.unit == "count"
        assert metric.timestamp == timestamp

    def test_metric_value_to_dict(self) -> None:
        """Test MetricValue to_dict method."""
        metric = MetricValue(
            name="test.metric",
            value=10.0,
            metric_type=MetricType.GAUGE,
            tags={"env": "prod"},
            unit="ms",
        )

        d = metric.to_dict()

        assert d["name"] == "test.metric"
        assert d["value"] == 10.0
        assert d["type"] == "gauge"
        assert d["tags"]["env"] == "prod"
        assert d["unit"] == "ms"
        assert "timestamp" in d


# ============================================================================
# InMemoryMetricsBackend Tests
# ============================================================================


class TestInMemoryMetricsBackend:
    """Tests for InMemoryMetricsBackend."""

    def test_backend_creation(self) -> None:
        """Test InMemoryMetricsBackend can be created."""
        backend = InMemoryMetricsBackend()
        assert backend is not None
        assert backend.max_size == 10000

    def test_backend_with_custom_size(self) -> None:
        """Test InMemoryMetricsBackend with custom max size."""
        backend = InMemoryMetricsBackend(max_size=100)
        assert backend.max_size == 100

    def test_record_metric(self) -> None:
        """Test recording a metric."""
        backend = InMemoryMetricsBackend()
        metric = MetricValue(
            name="test.metric",
            value=42.0,
            metric_type=MetricType.GAUGE,
        )

        backend.record(metric)

        assert len(backend.metrics) == 1
        assert backend.metrics[0].name == "test.metric"

    def test_record_multiple_metrics(self) -> None:
        """Test recording multiple metrics."""
        backend = InMemoryMetricsBackend()

        for i in range(5):
            metric = MetricValue(
                name=f"test.metric.{i}",
                value=float(i),
                metric_type=MetricType.COUNTER,
            )
            backend.record(metric)

        assert len(backend.metrics) == 5

    def test_max_size_limit(self) -> None:
        """Test max size limit is enforced."""
        backend = InMemoryMetricsBackend(max_size=10)

        for i in range(20):
            metric = MetricValue(
                name="test.metric",
                value=float(i),
                metric_type=MetricType.COUNTER,
            )
            backend.record(metric)

        assert len(backend.metrics) == 10
        # Should keep the last 10 metrics
        assert backend.metrics[0].value == 10.0

    def test_flush_is_noop(self) -> None:
        """Test flush is a no-op for in-memory backend."""
        backend = InMemoryMetricsBackend()
        metric = MetricValue(
            name="test.metric",
            value=1.0,
            metric_type=MetricType.GAUGE,
        )
        backend.record(metric)

        # Should not raise
        backend.flush()

        # Metrics should still be there
        assert len(backend.metrics) == 1

    def test_get_metrics_all(self) -> None:
        """Test getting all metrics."""
        backend = InMemoryMetricsBackend()

        for i in range(3):
            metric = MetricValue(
                name=f"metric.{i}",
                value=float(i),
                metric_type=MetricType.GAUGE,
            )
            backend.record(metric)

        metrics = backend.get_metrics()
        assert len(metrics) == 3

    def test_get_metrics_by_name(self) -> None:
        """Test filtering metrics by name."""
        backend = InMemoryMetricsBackend()

        backend.record(MetricValue("a.metric", 1.0, MetricType.GAUGE))
        backend.record(MetricValue("b.metric", 2.0, MetricType.GAUGE))
        backend.record(MetricValue("a.metric", 3.0, MetricType.GAUGE))

        metrics = backend.get_metrics(name="a.metric")
        assert len(metrics) == 2


# ============================================================================
# StructuredFormatter Tests
# ============================================================================


class TestStructuredFormatter:
    """Tests for StructuredFormatter."""

    def test_formatter_creation(self) -> None:
        """Test StructuredFormatter can be created."""
        formatter = StructuredFormatter()
        assert formatter is not None

    def test_formatter_with_options(self) -> None:
        """Test StructuredFormatter with custom options."""
        formatter = StructuredFormatter(
            include_timestamp=False,
            include_level=True,
            include_logger=False,
            include_location=True,
        )

        assert formatter.include_timestamp is False
        assert formatter.include_level is True
        assert formatter.include_logger is False
        assert formatter.include_location is True

    def test_format_basic_record(self) -> None:
        """Test formatting a basic log record."""
        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="/path/to/file.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)

        # Should be valid JSON
        data = json.loads(output)
        assert data["message"] == "Test message"
        assert data["level"] == "info"
        assert data["logger"] == "test.logger"

    def test_format_without_timestamp(self) -> None:
        """Test formatting without timestamp."""
        formatter = StructuredFormatter(include_timestamp=False)
        record = logging.LogRecord(
            name="test.logger",
            level=logging.WARNING,
            pathname="/path",
            lineno=1,
            msg="Warning message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)
        data = json.loads(output)

        assert "timestamp" not in data
        assert data["level"] == "warning"

    def test_format_with_location(self) -> None:
        """Test formatting with location info."""
        formatter = StructuredFormatter(include_location=True)
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="/app/module.py",
            lineno=100,
            msg="Error occurred",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)
        data = json.loads(output)

        assert "location" in data
        assert data["location"]["line"] == 100


# ============================================================================
# HumanReadableFormatter Tests
# ============================================================================


class TestHumanReadableFormatter:
    """Tests for HumanReadableFormatter."""

    def test_formatter_creation(self) -> None:
        """Test HumanReadableFormatter can be created."""
        formatter = HumanReadableFormatter()
        assert formatter is not None

    def test_format_basic_record(self) -> None:
        """Test formatting produces readable output."""
        formatter = HumanReadableFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="/path/to/file.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)

        # Should contain level and message
        assert "INFO" in output or "info" in output.lower()
        assert "Test message" in output


# ============================================================================
# StanceLogger Tests
# ============================================================================


class TestStanceLogger:
    """Tests for StanceLogger."""

    def test_logger_creation(self) -> None:
        """Test StanceLogger can be created."""
        logger = StanceLogger("test.module")
        assert logger is not None

    def test_logger_has_standard_methods(self) -> None:
        """Test StanceLogger has standard logging methods."""
        logger = StanceLogger("test")

        assert hasattr(logger, "debug")
        assert hasattr(logger, "info")
        assert hasattr(logger, "warning")
        assert hasattr(logger, "error")
        assert hasattr(logger, "critical")


# ============================================================================
# StanceMetrics Tests
# ============================================================================


class TestStanceMetrics:
    """Tests for StanceMetrics."""

    def test_metrics_creation(self) -> None:
        """Test StanceMetrics can be created."""
        backend = InMemoryMetricsBackend()
        metrics = StanceMetrics(backend)
        assert metrics is not None

    def test_counter(self) -> None:
        """Test recording a counter."""
        backend = InMemoryMetricsBackend()
        metrics = StanceMetrics(backend)

        metrics.counter("scan.count")

        assert len(backend.metrics) == 1
        assert backend.metrics[0].name == "scan.count"

    def test_counter_with_tags(self) -> None:
        """Test counter with tags."""
        backend = InMemoryMetricsBackend()
        metrics = StanceMetrics(backend)

        metrics.counter("findings.count", severity="critical")

        assert backend.metrics[0].tags["severity"] == "critical"

    def test_gauge(self) -> None:
        """Test setting a gauge value."""
        backend = InMemoryMetricsBackend()
        metrics = StanceMetrics(backend)

        metrics.gauge("assets.total", 500)

        assert backend.metrics[0].value == 500

    def test_timing(self) -> None:
        """Test recording timing."""
        backend = InMemoryMetricsBackend()
        metrics = StanceMetrics(backend)

        metrics.timing("scan.duration", 1500.0)

        assert backend.metrics[0].name == "scan.duration"
        assert backend.metrics[0].value == 1500.0


# ============================================================================
# configure_logging Tests
# ============================================================================


class TestConfigureLogging:
    """Tests for configure_logging function."""

    def test_configure_logging_exists(self) -> None:
        """Test configure_logging function exists."""
        assert configure_logging is not None
        assert callable(configure_logging)

    def test_configure_logging_returns_handler(self) -> None:
        """Test configure_logging can be called."""
        # Should not raise
        configure_logging(level="DEBUG")


# ============================================================================
# get_logger Tests
# ============================================================================


class TestGetLogger:
    """Tests for get_logger function."""

    def test_get_logger_exists(self) -> None:
        """Test get_logger function exists."""
        assert get_logger is not None
        assert callable(get_logger)

    def test_get_logger_returns_logger(self) -> None:
        """Test get_logger returns a logger."""
        logger = get_logger("test.module")
        assert logger is not None


# ============================================================================
# configure_metrics Tests
# ============================================================================


class TestConfigureMetrics:
    """Tests for configure_metrics function."""

    def test_configure_metrics_exists(self) -> None:
        """Test configure_metrics function exists."""
        assert configure_metrics is not None
        assert callable(configure_metrics)


# ============================================================================
# get_metrics Tests
# ============================================================================


class TestGetMetrics:
    """Tests for get_metrics function."""

    def test_get_metrics_exists(self) -> None:
        """Test get_metrics function exists."""
        assert get_metrics is not None
        assert callable(get_metrics)

    def test_get_metrics_returns_instance(self) -> None:
        """Test get_metrics returns a StanceMetrics instance."""
        metrics = get_metrics()
        assert metrics is not None


# ============================================================================
# CloudWatchMetricsBackend Tests
# ============================================================================


class TestCloudWatchMetricsBackend:
    """Tests for CloudWatchMetricsBackend."""

    def test_backend_creation(self) -> None:
        """Test CloudWatchMetricsBackend can be created."""
        backend = CloudWatchMetricsBackend(namespace="Stance")
        assert backend is not None

    def test_backend_has_required_methods(self) -> None:
        """Test CloudWatchMetricsBackend has required methods."""
        backend = CloudWatchMetricsBackend(namespace="Stance")

        assert hasattr(backend, "record")
        assert hasattr(backend, "flush")

    def test_backend_is_metrics_backend(self) -> None:
        """Test CloudWatchMetricsBackend is a MetricsBackend."""
        backend = CloudWatchMetricsBackend(namespace="Stance")
        assert isinstance(backend, MetricsBackend)


# ============================================================================
# SpanStatus Tests
# ============================================================================


class TestSpanStatus:
    """Tests for SpanStatus enum."""

    def test_span_status_ok(self) -> None:
        """Test OK span status."""
        assert SpanStatus.OK.value == "ok"

    def test_span_status_error(self) -> None:
        """Test ERROR span status."""
        assert SpanStatus.ERROR.value == "error"

    def test_span_status_cancelled(self) -> None:
        """Test CANCELLED span status."""
        assert SpanStatus.CANCELLED.value == "cancelled"


# ============================================================================
# SpanContext Tests
# ============================================================================


class TestSpanContext:
    """Tests for SpanContext dataclass."""

    def test_span_context_creation(self) -> None:
        """Test SpanContext can be created."""
        context = SpanContext(
            trace_id="abc123",
            span_id="def456",
        )

        assert context.trace_id == "abc123"
        assert context.span_id == "def456"
        assert context.parent_span_id is None
        assert context.sampled is True

    def test_span_context_with_parent(self) -> None:
        """Test SpanContext with parent span."""
        context = SpanContext(
            trace_id="abc123",
            span_id="def456",
            parent_span_id="ghi789",
        )

        assert context.parent_span_id == "ghi789"

    def test_span_context_new_root(self) -> None:
        """Test creating a new root context."""
        context = SpanContext.new_root()

        assert context.trace_id is not None
        assert len(context.trace_id) == 32
        assert context.span_id is not None
        assert len(context.span_id) == 16
        assert context.parent_span_id is None

    def test_span_context_new_child(self) -> None:
        """Test creating a child context."""
        parent = SpanContext.new_root()
        child = parent.new_child()

        assert child.trace_id == parent.trace_id
        assert child.span_id != parent.span_id
        assert child.parent_span_id == parent.span_id

    def test_span_context_to_dict(self) -> None:
        """Test SpanContext to_dict method."""
        context = SpanContext(
            trace_id="abc123",
            span_id="def456",
            parent_span_id="ghi789",
            sampled=False,
        )

        d = context.to_dict()

        assert d["trace_id"] == "abc123"
        assert d["span_id"] == "def456"
        assert d["parent_span_id"] == "ghi789"
        assert d["sampled"] is False

    def test_span_context_from_dict(self) -> None:
        """Test SpanContext from_dict method."""
        data = {
            "trace_id": "abc123",
            "span_id": "def456",
            "parent_span_id": "ghi789",
            "sampled": True,
        }

        context = SpanContext.from_dict(data)

        assert context.trace_id == "abc123"
        assert context.span_id == "def456"
        assert context.parent_span_id == "ghi789"


# ============================================================================
# Span Tests
# ============================================================================


class TestSpan:
    """Tests for Span dataclass."""

    def test_span_creation(self) -> None:
        """Test Span can be created."""
        context = SpanContext.new_root()
        span = Span(name="test.operation", context=context)

        assert span.name == "test.operation"
        assert span.context == context
        assert span.status == SpanStatus.OK
        assert span.end_time is None

    def test_span_set_attribute(self) -> None:
        """Test setting span attributes."""
        context = SpanContext.new_root()
        span = Span(name="test", context=context)

        span.set_attribute("http.method", "GET")
        span.set_attribute("http.status", 200)

        assert span.attributes["http.method"] == "GET"
        assert span.attributes["http.status"] == 200

    def test_span_add_event(self) -> None:
        """Test adding events to span."""
        context = SpanContext.new_root()
        span = Span(name="test", context=context)

        span.add_event("checkpoint", {"stage": "validation"})

        assert len(span.events) == 1
        assert span.events[0]["name"] == "checkpoint"
        assert span.events[0]["attributes"]["stage"] == "validation"

    def test_span_set_error_string(self) -> None:
        """Test setting error on span with string."""
        context = SpanContext.new_root()
        span = Span(name="test", context=context)

        span.set_error("Something went wrong")

        assert span.status == SpanStatus.ERROR
        assert span.error_message == "Something went wrong"

    def test_span_set_error_exception(self) -> None:
        """Test setting error on span with exception."""
        context = SpanContext.new_root()
        span = Span(name="test", context=context)

        try:
            raise ValueError("Invalid value")
        except ValueError as e:
            span.set_error(e)

        assert span.status == SpanStatus.ERROR
        assert "ValueError" in span.error_message
        assert "Invalid value" in span.error_message

    def test_span_end(self) -> None:
        """Test ending a span."""
        context = SpanContext.new_root()
        span = Span(name="test", context=context)

        assert span.end_time is None
        span.end()
        assert span.end_time is not None

    def test_span_duration_ms(self) -> None:
        """Test span duration calculation."""
        context = SpanContext.new_root()
        span = Span(name="test", context=context)

        assert span.duration_ms is None

        span.end()

        assert span.duration_ms is not None
        assert span.duration_ms >= 0

    def test_span_to_dict(self) -> None:
        """Test Span to_dict method."""
        context = SpanContext.new_root()
        span = Span(name="test.operation", context=context)
        span.set_attribute("key", "value")
        span.end()

        d = span.to_dict()

        assert d["name"] == "test.operation"
        assert d["trace_id"] == context.trace_id
        assert d["span_id"] == context.span_id
        assert d["status"] == "ok"
        assert d["attributes"]["key"] == "value"


# ============================================================================
# InMemoryTracingBackend Tests
# ============================================================================


class TestInMemoryTracingBackend:
    """Tests for InMemoryTracingBackend."""

    def test_backend_creation(self) -> None:
        """Test InMemoryTracingBackend can be created."""
        backend = InMemoryTracingBackend()
        assert backend is not None
        assert backend.max_size == 1000

    def test_backend_with_custom_size(self) -> None:
        """Test InMemoryTracingBackend with custom max size."""
        backend = InMemoryTracingBackend(max_size=50)
        assert backend.max_size == 50

    def test_record_span(self) -> None:
        """Test recording a span."""
        backend = InMemoryTracingBackend()
        context = SpanContext.new_root()
        span = Span(name="test", context=context)
        span.end()

        backend.record_span(span)

        assert len(backend.spans) == 1
        assert backend.spans[0].name == "test"

    def test_record_multiple_spans(self) -> None:
        """Test recording multiple spans."""
        backend = InMemoryTracingBackend()
        context = SpanContext.new_root()

        for i in range(5):
            span = Span(name=f"test.{i}", context=context.new_child())
            span.end()
            backend.record_span(span)

        assert len(backend.spans) == 5

    def test_max_size_limit(self) -> None:
        """Test max size limit is enforced."""
        backend = InMemoryTracingBackend(max_size=10)

        for i in range(20):
            context = SpanContext.new_root()
            span = Span(name=f"test.{i}", context=context)
            span.end()
            backend.record_span(span)

        assert len(backend.spans) == 10

    def test_get_trace(self) -> None:
        """Test getting all spans for a trace."""
        backend = InMemoryTracingBackend()
        root = SpanContext.new_root()

        # Create spans for same trace
        span1 = Span(name="root", context=root)
        span1.end()
        backend.record_span(span1)

        child = root.new_child()
        span2 = Span(name="child", context=child)
        span2.end()
        backend.record_span(span2)

        # Create span for different trace
        other = SpanContext.new_root()
        span3 = Span(name="other", context=other)
        span3.end()
        backend.record_span(span3)

        trace_spans = backend.get_trace(root.trace_id)
        assert len(trace_spans) == 2

    def test_get_spans_by_name(self) -> None:
        """Test filtering spans by name."""
        backend = InMemoryTracingBackend()

        for name in ["a.op", "b.op", "a.op"]:
            context = SpanContext.new_root()
            span = Span(name=name, context=context)
            span.end()
            backend.record_span(span)

        spans = backend.get_spans(name="a.op")
        assert len(spans) == 2

    def test_flush_is_noop(self) -> None:
        """Test flush is a no-op for in-memory backend."""
        backend = InMemoryTracingBackend()
        context = SpanContext.new_root()
        span = Span(name="test", context=context)
        span.end()
        backend.record_span(span)

        # Should not raise
        backend.flush()

        # Spans should still be there
        assert len(backend.spans) == 1

    def test_clear(self) -> None:
        """Test clearing all spans."""
        backend = InMemoryTracingBackend()
        context = SpanContext.new_root()
        span = Span(name="test", context=context)
        span.end()
        backend.record_span(span)

        backend.clear()

        assert len(backend.spans) == 0


# ============================================================================
# StanceTracer Tests
# ============================================================================


class TestStanceTracer:
    """Tests for StanceTracer."""

    def test_tracer_creation(self) -> None:
        """Test StanceTracer can be created."""
        backend = InMemoryTracingBackend()
        tracer = StanceTracer(backend)
        assert tracer is not None

    def test_start_span(self) -> None:
        """Test starting a span."""
        backend = InMemoryTracingBackend()
        tracer = StanceTracer(backend)

        span = tracer.start_span("test.operation")

        assert span.name == "test.operation"
        assert span.context is not None
        assert tracer.current_context == span.context

    def test_start_span_with_attributes(self) -> None:
        """Test starting a span with initial attributes."""
        backend = InMemoryTracingBackend()
        tracer = StanceTracer(backend)

        span = tracer.start_span(
            "test.operation",
            attributes={"key": "value"},
        )

        assert span.attributes["key"] == "value"

    def test_end_span(self) -> None:
        """Test ending a span."""
        backend = InMemoryTracingBackend()
        tracer = StanceTracer(backend)

        span = tracer.start_span("test")
        tracer.end_span(span)

        assert span.end_time is not None
        assert len(backend.spans) == 1

    def test_span_context_manager(self) -> None:
        """Test span as context manager."""
        backend = InMemoryTracingBackend()
        tracer = StanceTracer(backend)

        with tracer.span("test.operation") as span:
            span.set_attribute("step", "processing")

        assert len(backend.spans) == 1
        assert backend.spans[0].end_time is not None

    def test_span_context_manager_with_error(self) -> None:
        """Test span context manager records errors."""
        backend = InMemoryTracingBackend()
        tracer = StanceTracer(backend)

        with pytest.raises(ValueError):
            with tracer.span("test.operation") as span:
                raise ValueError("Something went wrong")

        assert len(backend.spans) == 1
        assert backend.spans[0].status == SpanStatus.ERROR

    def test_nested_spans(self) -> None:
        """Test nested spans maintain parent relationship."""
        backend = InMemoryTracingBackend()
        tracer = StanceTracer(backend)

        with tracer.span("parent") as parent_span:
            with tracer.span("child") as child_span:
                assert child_span.context.parent_span_id == parent_span.context.span_id
                assert child_span.context.trace_id == parent_span.context.trace_id

        assert len(backend.spans) == 2

    def test_trace_scan(self) -> None:
        """Test trace_scan convenience method."""
        backend = InMemoryTracingBackend()
        tracer = StanceTracer(backend)

        with tracer.trace_scan("scan-123", "production"):
            pass

        assert len(backend.spans) == 1
        assert backend.spans[0].name == "scan"
        assert backend.spans[0].attributes["scan.id"] == "scan-123"

    def test_trace_collector(self) -> None:
        """Test trace_collector convenience method."""
        backend = InMemoryTracingBackend()
        tracer = StanceTracer(backend)

        with tracer.trace_collector("aws_iam", "us-east-1"):
            pass

        assert len(backend.spans) == 1
        assert "collector.aws_iam" in backend.spans[0].name
        assert backend.spans[0].attributes["collector.region"] == "us-east-1"

    def test_trace_policy_evaluation(self) -> None:
        """Test trace_policy_evaluation convenience method."""
        backend = InMemoryTracingBackend()
        tracer = StanceTracer(backend)

        with tracer.trace_policy_evaluation("aws-s3-001", 50):
            pass

        assert len(backend.spans) == 1
        assert backend.spans[0].attributes["policy.id"] == "aws-s3-001"
        assert backend.spans[0].attributes["policy.asset_count"] == 50

    def test_trace_api_request(self) -> None:
        """Test trace_api_request convenience method."""
        backend = InMemoryTracingBackend()
        tracer = StanceTracer(backend)

        with tracer.trace_api_request("GET", "/api/findings"):
            pass

        assert len(backend.spans) == 1
        assert backend.spans[0].attributes["http.method"] == "GET"
        assert backend.spans[0].attributes["http.route"] == "/api/findings"

    def test_trace_query(self) -> None:
        """Test trace_query convenience method."""
        backend = InMemoryTracingBackend()
        tracer = StanceTracer(backend)

        with tracer.trace_query("natural_language", "athena"):
            pass

        assert len(backend.spans) == 1
        assert backend.spans[0].attributes["query.type"] == "natural_language"
        assert backend.spans[0].attributes["query.backend"] == "athena"

    def test_flush(self) -> None:
        """Test flush method."""
        backend = InMemoryTracingBackend()
        tracer = StanceTracer(backend)

        with tracer.span("test"):
            pass

        # Should not raise
        tracer.flush()


# ============================================================================
# XRayTracingBackend Tests
# ============================================================================


class TestXRayTracingBackend:
    """Tests for XRayTracingBackend."""

    def test_backend_creation(self) -> None:
        """Test XRayTracingBackend can be created."""
        backend = XRayTracingBackend(region="us-east-1")
        assert backend is not None

    def test_backend_has_required_methods(self) -> None:
        """Test XRayTracingBackend has required methods."""
        backend = XRayTracingBackend()

        assert hasattr(backend, "record_span")
        assert hasattr(backend, "flush")

    def test_backend_is_tracing_backend(self) -> None:
        """Test XRayTracingBackend is a TracingBackend."""
        backend = XRayTracingBackend()
        assert isinstance(backend, TracingBackend)


# ============================================================================
# CloudTraceBackend Tests
# ============================================================================


class TestCloudTraceBackend:
    """Tests for CloudTraceBackend."""

    def test_backend_creation(self) -> None:
        """Test CloudTraceBackend can be created."""
        backend = CloudTraceBackend(project_id="test-project")
        assert backend is not None

    def test_backend_has_required_methods(self) -> None:
        """Test CloudTraceBackend has required methods."""
        backend = CloudTraceBackend(project_id="test-project")

        assert hasattr(backend, "record_span")
        assert hasattr(backend, "flush")

    def test_backend_is_tracing_backend(self) -> None:
        """Test CloudTraceBackend is a TracingBackend."""
        backend = CloudTraceBackend(project_id="test-project")
        assert isinstance(backend, TracingBackend)


# ============================================================================
# ApplicationInsightsBackend Tests
# ============================================================================


class TestApplicationInsightsBackend:
    """Tests for ApplicationInsightsBackend."""

    def test_backend_creation(self) -> None:
        """Test ApplicationInsightsBackend can be created."""
        backend = ApplicationInsightsBackend()
        assert backend is not None

    def test_backend_has_required_methods(self) -> None:
        """Test ApplicationInsightsBackend has required methods."""
        backend = ApplicationInsightsBackend()

        assert hasattr(backend, "record_span")
        assert hasattr(backend, "flush")

    def test_backend_is_tracing_backend(self) -> None:
        """Test ApplicationInsightsBackend is a TracingBackend."""
        backend = ApplicationInsightsBackend()
        assert isinstance(backend, TracingBackend)


# ============================================================================
# configure_tracing Tests
# ============================================================================


class TestConfigureTracing:
    """Tests for configure_tracing function."""

    def test_configure_tracing_exists(self) -> None:
        """Test configure_tracing function exists."""
        assert configure_tracing is not None
        assert callable(configure_tracing)

    def test_configure_tracing_returns_tracer(self) -> None:
        """Test configure_tracing returns a tracer."""
        backend = InMemoryTracingBackend()
        tracer = configure_tracing(backend)
        assert isinstance(tracer, StanceTracer)


# ============================================================================
# get_tracer Tests
# ============================================================================


class TestGetTracer:
    """Tests for get_tracer function."""

    def test_get_tracer_exists(self) -> None:
        """Test get_tracer function exists."""
        assert get_tracer is not None
        assert callable(get_tracer)

    def test_get_tracer_returns_instance(self) -> None:
        """Test get_tracer returns a StanceTracer instance."""
        tracer = get_tracer()
        assert tracer is not None
        assert isinstance(tracer, StanceTracer)
