"""
Metrics collection for Mantissa Stance.

Provides metrics collection and reporting for monitoring
scan performance, finding trends, and system health.
"""

from __future__ import annotations

import os
import time
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Iterator


class MetricType(Enum):
    """Types of metrics."""

    COUNTER = "counter"  # Monotonically increasing value
    GAUGE = "gauge"  # Value that can go up or down
    HISTOGRAM = "histogram"  # Distribution of values
    TIMER = "timer"  # Duration measurements


@dataclass
class MetricValue:
    """A single metric value."""

    name: str
    value: float
    metric_type: MetricType
    timestamp: datetime = field(default_factory=datetime.utcnow)
    tags: dict[str, str] = field(default_factory=dict)
    unit: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "value": self.value,
            "type": self.metric_type.value,
            "timestamp": self.timestamp.isoformat(),
            "tags": self.tags,
            "unit": self.unit,
        }


class MetricsBackend(ABC):
    """Abstract base class for metrics backends."""

    @abstractmethod
    def record(self, metric: MetricValue) -> None:
        """Record a metric value."""
        pass

    @abstractmethod
    def flush(self) -> None:
        """Flush any buffered metrics."""
        pass


class InMemoryMetricsBackend(MetricsBackend):
    """
    In-memory metrics backend for testing and local development.

    Stores metrics in memory and provides query methods.
    """

    def __init__(self, max_size: int = 10000):
        """
        Initialize in-memory backend.

        Args:
            max_size: Maximum number of metrics to store
        """
        self.max_size = max_size
        self.metrics: list[MetricValue] = []

    def record(self, metric: MetricValue) -> None:
        """Record a metric value."""
        self.metrics.append(metric)
        if len(self.metrics) > self.max_size:
            self.metrics = self.metrics[-self.max_size :]

    def flush(self) -> None:
        """No-op for in-memory backend."""
        pass

    def get_metrics(
        self,
        name: str | None = None,
        since: datetime | None = None,
    ) -> list[MetricValue]:
        """
        Query stored metrics.

        Args:
            name: Filter by metric name
            since: Filter by timestamp

        Returns:
            List of matching metrics
        """
        result = []
        for metric in self.metrics:
            if name and metric.name != name:
                continue
            if since and metric.timestamp < since:
                continue
            result.append(metric)
        return result

    def clear(self) -> None:
        """Clear all stored metrics."""
        self.metrics.clear()


class CloudWatchMetricsBackend(MetricsBackend):
    """
    AWS CloudWatch metrics backend.

    Sends metrics to CloudWatch for monitoring and alerting.
    """

    def __init__(
        self,
        namespace: str = "MantissaStance",
        region: str = "us-east-1",
        buffer_size: int = 20,
    ):
        """
        Initialize CloudWatch backend.

        Args:
            namespace: CloudWatch namespace
            region: AWS region
            buffer_size: Number of metrics to buffer before sending
        """
        self.namespace = namespace
        self.region = region
        self.buffer_size = buffer_size
        self._buffer: list[MetricValue] = []
        self._client = None

    def _get_client(self):
        """Get or create CloudWatch client."""
        if self._client is None:
            import boto3

            self._client = boto3.client("cloudwatch", region_name=self.region)
        return self._client

    def record(self, metric: MetricValue) -> None:
        """Record a metric value."""
        self._buffer.append(metric)
        if len(self._buffer) >= self.buffer_size:
            self.flush()

    def flush(self) -> None:
        """Send buffered metrics to CloudWatch."""
        if not self._buffer:
            return

        try:
            client = self._get_client()

            metric_data = []
            for metric in self._buffer:
                data = {
                    "MetricName": metric.name,
                    "Value": metric.value,
                    "Timestamp": metric.timestamp,
                    "Unit": self._map_unit(metric.unit),
                }

                if metric.tags:
                    data["Dimensions"] = [
                        {"Name": k, "Value": v} for k, v in metric.tags.items()
                    ]

                metric_data.append(data)

            # CloudWatch limits to 1000 metrics per call
            for i in range(0, len(metric_data), 1000):
                batch = metric_data[i : i + 1000]
                client.put_metric_data(Namespace=self.namespace, MetricData=batch)

            self._buffer.clear()

        except Exception:
            # Log error but don't fail
            pass

    def _map_unit(self, unit: str) -> str:
        """Map unit to CloudWatch unit."""
        unit_map = {
            "seconds": "Seconds",
            "milliseconds": "Milliseconds",
            "bytes": "Bytes",
            "count": "Count",
            "percent": "Percent",
            "": "None",
        }
        return unit_map.get(unit, "None")


class StanceMetrics:
    """
    High-level metrics collection for Stance.

    Provides convenient methods for recording common metrics.
    """

    def __init__(self, backend: MetricsBackend | None = None):
        """
        Initialize metrics collector.

        Args:
            backend: Metrics backend (default: InMemoryMetricsBackend)
        """
        self.backend = backend or InMemoryMetricsBackend()
        self._default_tags: dict[str, str] = {}

    def set_default_tags(self, **tags: str) -> None:
        """Set default tags for all metrics."""
        self._default_tags.update(tags)

    def _record(
        self,
        name: str,
        value: float,
        metric_type: MetricType,
        unit: str = "",
        **tags: str,
    ) -> None:
        """Record a metric with merged tags."""
        all_tags = {**self._default_tags, **tags}
        metric = MetricValue(
            name=name,
            value=value,
            metric_type=metric_type,
            unit=unit,
            tags=all_tags,
        )
        self.backend.record(metric)

    def counter(self, name: str, value: float = 1, **tags: str) -> None:
        """
        Increment a counter.

        Args:
            name: Metric name
            value: Increment value (default: 1)
            **tags: Additional tags
        """
        self._record(name, value, MetricType.COUNTER, "count", **tags)

    def gauge(self, name: str, value: float, unit: str = "", **tags: str) -> None:
        """
        Set a gauge value.

        Args:
            name: Metric name
            value: Current value
            unit: Unit of measurement
            **tags: Additional tags
        """
        self._record(name, value, MetricType.GAUGE, unit, **tags)

    def timing(self, name: str, duration_seconds: float, **tags: str) -> None:
        """
        Record a timing measurement.

        Args:
            name: Metric name
            duration_seconds: Duration in seconds
            **tags: Additional tags
        """
        self._record(name, duration_seconds, MetricType.TIMER, "seconds", **tags)

    @contextmanager
    def timer(self, name: str, **tags: str) -> Iterator[None]:
        """
        Context manager for timing a block of code.

        Args:
            name: Metric name
            **tags: Additional tags

        Yields:
            None
        """
        start = time.perf_counter()
        try:
            yield
        finally:
            duration = time.perf_counter() - start
            self.timing(name, duration, **tags)

    # Scan metrics

    def scan_started(self, scan_id: str, config_name: str = "default") -> None:
        """Record scan start."""
        self.counter("scans.started", scan_id=scan_id, config=config_name)

    def scan_completed(
        self,
        scan_id: str,
        duration_seconds: float,
        asset_count: int,
        finding_count: int,
    ) -> None:
        """Record scan completion."""
        self.counter("scans.completed", scan_id=scan_id)
        self.timing("scans.duration", duration_seconds, scan_id=scan_id)
        self.gauge("scans.asset_count", asset_count, scan_id=scan_id)
        self.gauge("scans.finding_count", finding_count, scan_id=scan_id)

    def scan_failed(self, scan_id: str, error_type: str = "unknown") -> None:
        """Record scan failure."""
        self.counter("scans.failed", scan_id=scan_id, error_type=error_type)

    # Collector metrics

    def collector_started(self, collector_name: str, region: str = "") -> None:
        """Record collector start."""
        self.counter("collectors.started", collector=collector_name, region=region)

    def collector_completed(
        self,
        collector_name: str,
        duration_seconds: float,
        asset_count: int,
        region: str = "",
    ) -> None:
        """Record collector completion."""
        self.counter("collectors.completed", collector=collector_name, region=region)
        self.timing(
            "collectors.duration",
            duration_seconds,
            collector=collector_name,
            region=region,
        )
        self.gauge(
            "collectors.assets",
            asset_count,
            collector=collector_name,
            region=region,
        )

    def collector_failed(
        self, collector_name: str, error_type: str = "unknown", region: str = ""
    ) -> None:
        """Record collector failure."""
        self.counter(
            "collectors.failed",
            collector=collector_name,
            error_type=error_type,
            region=region,
        )

    # Finding metrics

    def finding_generated(self, severity: str, rule_id: str) -> None:
        """Record finding generation."""
        self.counter("findings.generated", severity=severity, rule_id=rule_id)

    def findings_by_severity(self, counts: dict[str, int]) -> None:
        """Record finding counts by severity."""
        for severity, count in counts.items():
            self.gauge("findings.count", count, severity=severity)

    # Policy metrics

    def policy_evaluated(self, policy_id: str, duration_seconds: float) -> None:
        """Record policy evaluation."""
        self.counter("policies.evaluated", policy_id=policy_id)
        self.timing("policies.duration", duration_seconds, policy_id=policy_id)

    def policies_loaded(self, count: int) -> None:
        """Record number of policies loaded."""
        self.gauge("policies.loaded", count)

    # API metrics

    def api_request(
        self,
        endpoint: str,
        method: str,
        status_code: int,
        duration_seconds: float,
    ) -> None:
        """Record API request."""
        self.counter(
            "api.requests",
            endpoint=endpoint,
            method=method,
            status=str(status_code),
        )
        self.timing(
            "api.duration",
            duration_seconds,
            endpoint=endpoint,
            method=method,
        )

    def flush(self) -> None:
        """Flush any buffered metrics."""
        self.backend.flush()


# Global metrics instance
_metrics: StanceMetrics | None = None


def get_metrics() -> StanceMetrics:
    """
    Get the global metrics instance.

    Returns:
        StanceMetrics instance
    """
    global _metrics
    if _metrics is None:
        # Configure based on environment
        backend_type = os.getenv("STANCE_METRICS_BACKEND", "memory")
        if backend_type == "cloudwatch":
            backend = CloudWatchMetricsBackend(
                namespace=os.getenv("STANCE_METRICS_NAMESPACE", "MantissaStance"),
                region=os.getenv("AWS_REGION", "us-east-1"),
            )
        else:
            backend = InMemoryMetricsBackend()
        _metrics = StanceMetrics(backend=backend)
    return _metrics


def configure_metrics(backend: MetricsBackend) -> StanceMetrics:
    """
    Configure the global metrics instance.

    Args:
        backend: Metrics backend to use

    Returns:
        Configured StanceMetrics instance
    """
    global _metrics
    _metrics = StanceMetrics(backend=backend)
    return _metrics
