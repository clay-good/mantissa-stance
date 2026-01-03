"""
Distributed tracing for Mantissa Stance.

Provides trace context propagation and span recording for
tracking request flows across collectors, evaluators, and APIs.
Supports multiple backends including in-memory, AWS X-Ray,
Google Cloud Trace, and Azure Application Insights.
"""

from __future__ import annotations

import os
import time
import uuid
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Iterator


class SpanStatus(Enum):
    """Status of a span."""

    OK = "ok"
    ERROR = "error"
    CANCELLED = "cancelled"


@dataclass
class SpanContext:
    """
    Context for trace propagation.

    Contains trace and span IDs for correlating spans
    across service boundaries.
    """

    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    sampled: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "sampled": self.sampled,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SpanContext:
        """Create from dictionary."""
        return cls(
            trace_id=data["trace_id"],
            span_id=data["span_id"],
            parent_span_id=data.get("parent_span_id"),
            sampled=data.get("sampled", True),
        )

    @classmethod
    def new_root(cls, sampled: bool = True) -> SpanContext:
        """Create a new root span context."""
        return cls(
            trace_id=cls._generate_trace_id(),
            span_id=cls._generate_span_id(),
            parent_span_id=None,
            sampled=sampled,
        )

    def new_child(self) -> SpanContext:
        """Create a child span context."""
        return SpanContext(
            trace_id=self.trace_id,
            span_id=self._generate_span_id(),
            parent_span_id=self.span_id,
            sampled=self.sampled,
        )

    @staticmethod
    def _generate_trace_id() -> str:
        """Generate a unique trace ID."""
        return uuid.uuid4().hex

    @staticmethod
    def _generate_span_id() -> str:
        """Generate a unique span ID."""
        return uuid.uuid4().hex[:16]


@dataclass
class Span:
    """
    A single span in a trace.

    Represents a unit of work with timing, status, and metadata.
    """

    name: str
    context: SpanContext
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: datetime | None = None
    status: SpanStatus = SpanStatus.OK
    attributes: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    error_message: str | None = None

    def set_attribute(self, key: str, value: Any) -> None:
        """Set a span attribute."""
        self.attributes[key] = value

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        """Add an event to the span."""
        self.events.append(
            {
                "name": name,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "attributes": attributes or {},
            }
        )

    def set_error(self, error: str | Exception) -> None:
        """Mark the span as errored."""
        self.status = SpanStatus.ERROR
        if isinstance(error, Exception):
            self.error_message = f"{type(error).__name__}: {str(error)}"
        else:
            self.error_message = str(error)

    def end(self) -> None:
        """End the span."""
        self.end_time = datetime.utcnow()

    @property
    def duration_ms(self) -> float | None:
        """Get span duration in milliseconds."""
        if self.end_time is None:
            return None
        delta = self.end_time - self.start_time
        return delta.total_seconds() * 1000

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "trace_id": self.context.trace_id,
            "span_id": self.context.span_id,
            "parent_span_id": self.context.parent_span_id,
            "start_time": self.start_time.isoformat() + "Z",
            "end_time": self.end_time.isoformat() + "Z" if self.end_time else None,
            "duration_ms": self.duration_ms,
            "status": self.status.value,
            "attributes": self.attributes,
            "events": self.events,
            "error_message": self.error_message,
        }


class TracingBackend(ABC):
    """Abstract base class for tracing backends."""

    @abstractmethod
    def record_span(self, span: Span) -> None:
        """Record a completed span."""
        pass

    @abstractmethod
    def flush(self) -> None:
        """Flush any buffered spans."""
        pass


class InMemoryTracingBackend(TracingBackend):
    """
    In-memory tracing backend for testing and local development.

    Stores spans in memory and provides query methods.
    """

    def __init__(self, max_size: int = 1000):
        """
        Initialize in-memory backend.

        Args:
            max_size: Maximum number of spans to store
        """
        self.max_size = max_size
        self.spans: list[Span] = []

    def record_span(self, span: Span) -> None:
        """Record a span."""
        self.spans.append(span)
        if len(self.spans) > self.max_size:
            self.spans = self.spans[-self.max_size :]

    def flush(self) -> None:
        """No-op for in-memory backend."""
        pass

    def get_trace(self, trace_id: str) -> list[Span]:
        """Get all spans for a trace."""
        return [s for s in self.spans if s.context.trace_id == trace_id]

    def get_spans(
        self,
        name: str | None = None,
        since: datetime | None = None,
    ) -> list[Span]:
        """
        Query stored spans.

        Args:
            name: Filter by span name
            since: Filter by start time

        Returns:
            List of matching spans
        """
        result = []
        for span in self.spans:
            if name and span.name != name:
                continue
            if since and span.start_time < since:
                continue
            result.append(span)
        return result

    def clear(self) -> None:
        """Clear all stored spans."""
        self.spans.clear()


class XRayTracingBackend(TracingBackend):
    """
    AWS X-Ray tracing backend.

    Sends traces to X-Ray for distributed tracing visualization.
    """

    def __init__(
        self,
        region: str = "us-east-1",
        service_name: str = "mantissa-stance",
        buffer_size: int = 10,
    ):
        """
        Initialize X-Ray backend.

        Args:
            region: AWS region
            service_name: Service name for X-Ray
            buffer_size: Number of spans to buffer before sending
        """
        self.region = region
        self.service_name = service_name
        self.buffer_size = buffer_size
        self._buffer: list[Span] = []
        self._client = None

    def _get_client(self):
        """Get or create X-Ray client."""
        if self._client is None:
            import boto3

            self._client = boto3.client("xray", region_name=self.region)
        return self._client

    def record_span(self, span: Span) -> None:
        """Record a span."""
        self._buffer.append(span)
        if len(self._buffer) >= self.buffer_size:
            self.flush()

    def flush(self) -> None:
        """Send buffered spans to X-Ray."""
        if not self._buffer:
            return

        try:
            client = self._get_client()

            # Group spans by trace
            traces: dict[str, list[Span]] = {}
            for span in self._buffer:
                trace_id = span.context.trace_id
                if trace_id not in traces:
                    traces[trace_id] = []
                traces[trace_id].append(span)

            # Convert to X-Ray documents
            documents = []
            for trace_id, spans in traces.items():
                for span in spans:
                    doc = self._span_to_xray(span)
                    documents.append(doc)

            # Send to X-Ray
            if documents:
                client.put_trace_segments(TraceSegmentDocuments=documents)

            self._buffer.clear()

        except Exception:
            # Log error but don't fail
            pass

    def _span_to_xray(self, span: Span) -> str:
        """Convert span to X-Ray segment document."""
        import json

        # X-Ray uses a specific trace ID format
        xray_trace_id = f"1-{span.context.trace_id[:8]}-{span.context.trace_id[8:32]}"

        segment = {
            "name": self.service_name,
            "id": span.context.span_id,
            "trace_id": xray_trace_id,
            "start_time": span.start_time.timestamp(),
            "end_time": span.end_time.timestamp() if span.end_time else time.time(),
            "annotations": {
                "span_name": span.name,
            },
            "metadata": {
                "attributes": span.attributes,
            },
        }

        if span.context.parent_span_id:
            segment["parent_id"] = span.context.parent_span_id
            segment["type"] = "subsegment"

        if span.status == SpanStatus.ERROR:
            segment["fault"] = True
            if span.error_message:
                segment["cause"] = {"message": span.error_message}

        return json.dumps(segment)


class CloudTraceBackend(TracingBackend):
    """
    Google Cloud Trace backend.

    Sends traces to Cloud Trace for distributed tracing visualization.
    """

    def __init__(
        self,
        project_id: str,
        service_name: str = "mantissa-stance",
        buffer_size: int = 10,
    ):
        """
        Initialize Cloud Trace backend.

        Args:
            project_id: GCP project ID
            service_name: Service name for traces
            buffer_size: Number of spans to buffer before sending
        """
        self.project_id = project_id
        self.service_name = service_name
        self.buffer_size = buffer_size
        self._buffer: list[Span] = []
        self._client = None

    def _get_client(self):
        """Get or create Cloud Trace client."""
        if self._client is None:
            from google.cloud import trace_v2

            self._client = trace_v2.TraceServiceClient()
        return self._client

    def record_span(self, span: Span) -> None:
        """Record a span."""
        self._buffer.append(span)
        if len(self._buffer) >= self.buffer_size:
            self.flush()

    def flush(self) -> None:
        """Send buffered spans to Cloud Trace."""
        if not self._buffer:
            return

        try:
            client = self._get_client()
            from google.cloud.trace_v2 import types

            spans_to_send = []
            for span in self._buffer:
                cloud_span = types.Span(
                    name=f"projects/{self.project_id}/traces/{span.context.trace_id}/spans/{span.context.span_id}",
                    span_id=span.context.span_id,
                    parent_span_id=span.context.parent_span_id or "",
                    display_name=types.TruncatableString(value=span.name),
                    start_time=span.start_time,
                    end_time=span.end_time or datetime.utcnow(),
                )

                if span.status == SpanStatus.ERROR:
                    cloud_span.status.code = 2  # ERROR
                    if span.error_message:
                        cloud_span.status.message = span.error_message

                spans_to_send.append(cloud_span)

            # Batch write spans
            for span_obj in spans_to_send:
                client.create_span(name=span_obj.name, span=span_obj)

            self._buffer.clear()

        except Exception:
            # Log error but don't fail
            pass


class ApplicationInsightsBackend(TracingBackend):
    """
    Azure Application Insights tracing backend.

    Sends traces to Application Insights for distributed tracing.
    """

    def __init__(
        self,
        connection_string: str | None = None,
        service_name: str = "mantissa-stance",
        buffer_size: int = 10,
    ):
        """
        Initialize Application Insights backend.

        Args:
            connection_string: Application Insights connection string
            service_name: Service name for traces
            buffer_size: Number of spans to buffer before sending
        """
        self.connection_string = connection_string or os.getenv(
            "APPLICATIONINSIGHTS_CONNECTION_STRING"
        )
        self.service_name = service_name
        self.buffer_size = buffer_size
        self._buffer: list[Span] = []
        self._client = None

    def _get_client(self):
        """Get or create Application Insights client."""
        if self._client is None:
            from azure.monitor.opentelemetry.exporter import AzureMonitorTraceExporter

            self._client = AzureMonitorTraceExporter(
                connection_string=self.connection_string
            )
        return self._client

    def record_span(self, span: Span) -> None:
        """Record a span."""
        self._buffer.append(span)
        if len(self._buffer) >= self.buffer_size:
            self.flush()

    def flush(self) -> None:
        """Send buffered spans to Application Insights."""
        if not self._buffer:
            return

        try:
            # Application Insights export requires OpenTelemetry SDK
            # For simplicity, we'll use HTTP directly to the ingestion endpoint
            self._send_spans_http()
            self._buffer.clear()

        except Exception:
            # Log error but don't fail
            pass

    def _send_spans_http(self) -> None:
        """Send spans via HTTP to Application Insights."""
        import json
        import urllib.request

        if not self.connection_string:
            return

        # Parse connection string
        parts = dict(p.split("=", 1) for p in self.connection_string.split(";"))
        ingestion_endpoint = parts.get(
            "IngestionEndpoint", "https://dc.services.visualstudio.com"
        )
        instrumentation_key = parts.get("InstrumentationKey", "")

        if not instrumentation_key:
            return

        # Convert spans to Application Insights format
        telemetry_items = []
        for span in self._buffer:
            item = {
                "name": "Microsoft.ApplicationInsights.Request"
                if not span.context.parent_span_id
                else "Microsoft.ApplicationInsights.RemoteDependency",
                "time": span.start_time.isoformat() + "Z",
                "iKey": instrumentation_key,
                "tags": {
                    "ai.operation.id": span.context.trace_id,
                    "ai.operation.parentId": span.context.parent_span_id or "",
                    "ai.cloud.role": self.service_name,
                },
                "data": {
                    "baseType": "RequestData"
                    if not span.context.parent_span_id
                    else "RemoteDependencyData",
                    "baseData": {
                        "id": span.context.span_id,
                        "name": span.name,
                        "duration": self._format_duration(span.duration_ms or 0),
                        "success": span.status != SpanStatus.ERROR,
                        "properties": span.attributes,
                    },
                },
            }
            telemetry_items.append(item)

        # Send to Application Insights
        url = f"{ingestion_endpoint}/v2/track"
        data = json.dumps(telemetry_items).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=10)

    def _format_duration(self, duration_ms: float) -> str:
        """Format duration for Application Insights."""
        total_seconds = duration_ms / 1000
        hours = int(total_seconds // 3600)
        minutes = int((total_seconds % 3600) // 60)
        seconds = total_seconds % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:06.3f}"


class StanceTracer:
    """
    High-level tracing interface for Stance.

    Provides convenient methods for creating and managing spans.
    """

    def __init__(self, backend: TracingBackend | None = None):
        """
        Initialize tracer.

        Args:
            backend: Tracing backend (default: InMemoryTracingBackend)
        """
        self.backend = backend or InMemoryTracingBackend()
        self._current_context: SpanContext | None = None

    @property
    def current_context(self) -> SpanContext | None:
        """Get the current span context."""
        return self._current_context

    def start_span(
        self,
        name: str,
        parent: SpanContext | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> Span:
        """
        Start a new span.

        Args:
            name: Span name
            parent: Parent span context (uses current if not provided)
            attributes: Initial attributes

        Returns:
            New span
        """
        if parent is None:
            parent = self._current_context

        if parent is not None:
            context = parent.new_child()
        else:
            context = SpanContext.new_root()

        span = Span(name=name, context=context)
        if attributes:
            span.attributes.update(attributes)

        self._current_context = context
        return span

    def end_span(self, span: Span) -> None:
        """
        End a span and record it.

        Args:
            span: The span to end
        """
        span.end()
        self.backend.record_span(span)

        # Restore parent context
        if span.context.parent_span_id:
            self._current_context = SpanContext(
                trace_id=span.context.trace_id,
                span_id=span.context.parent_span_id,
                parent_span_id=None,  # We don't track grandparent
                sampled=span.context.sampled,
            )
        else:
            self._current_context = None

    @contextmanager
    def span(
        self,
        name: str,
        parent: SpanContext | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> Iterator[Span]:
        """
        Context manager for creating spans.

        Args:
            name: Span name
            parent: Parent span context
            attributes: Initial attributes

        Yields:
            The span being traced
        """
        span = self.start_span(name, parent, attributes)
        try:
            yield span
        except Exception as e:
            span.set_error(e)
            raise
        finally:
            self.end_span(span)

    # Convenience methods for common operations

    def trace_scan(
        self,
        scan_id: str,
        config_name: str = "default",
    ) -> Iterator[Span]:
        """
        Context manager for tracing a scan.

        Args:
            scan_id: Scan identifier
            config_name: Configuration name

        Yields:
            The scan span
        """
        return self.span(
            "scan",
            attributes={
                "scan.id": scan_id,
                "scan.config": config_name,
            },
        )

    def trace_collector(
        self,
        collector_name: str,
        region: str = "",
    ) -> Iterator[Span]:
        """
        Context manager for tracing a collector.

        Args:
            collector_name: Name of the collector
            region: Cloud region

        Yields:
            The collector span
        """
        return self.span(
            f"collector.{collector_name}",
            attributes={
                "collector.name": collector_name,
                "collector.region": region,
            },
        )

    def trace_policy_evaluation(
        self,
        policy_id: str,
        asset_count: int = 0,
    ) -> Iterator[Span]:
        """
        Context manager for tracing policy evaluation.

        Args:
            policy_id: Policy identifier
            asset_count: Number of assets being evaluated

        Yields:
            The evaluation span
        """
        return self.span(
            f"policy.evaluate.{policy_id}",
            attributes={
                "policy.id": policy_id,
                "policy.asset_count": asset_count,
            },
        )

    def trace_api_request(
        self,
        method: str,
        endpoint: str,
    ) -> Iterator[Span]:
        """
        Context manager for tracing an API request.

        Args:
            method: HTTP method
            endpoint: API endpoint

        Yields:
            The request span
        """
        return self.span(
            f"api.{method.lower()}.{endpoint}",
            attributes={
                "http.method": method,
                "http.route": endpoint,
            },
        )

    def trace_query(
        self,
        query_type: str,
        backend: str = "unknown",
    ) -> Iterator[Span]:
        """
        Context manager for tracing a query.

        Args:
            query_type: Type of query (sql, natural_language)
            backend: Query backend (athena, bigquery, etc.)

        Yields:
            The query span
        """
        return self.span(
            f"query.{query_type}",
            attributes={
                "query.type": query_type,
                "query.backend": backend,
            },
        )

    def flush(self) -> None:
        """Flush any buffered spans."""
        self.backend.flush()


# Global tracer instance
_tracer: StanceTracer | None = None


def get_tracer() -> StanceTracer:
    """
    Get the global tracer instance.

    Returns:
        StanceTracer instance
    """
    global _tracer
    if _tracer is None:
        # Configure based on environment
        backend_type = os.getenv("STANCE_TRACING_BACKEND", "memory")
        backend: TracingBackend

        if backend_type == "xray":
            backend = XRayTracingBackend(
                region=os.getenv("AWS_REGION", "us-east-1"),
            )
        elif backend_type == "cloudtrace":
            project_id = os.getenv("GCP_PROJECT_ID", "")
            if project_id:
                backend = CloudTraceBackend(project_id=project_id)
            else:
                backend = InMemoryTracingBackend()
        elif backend_type == "appinsights":
            backend = ApplicationInsightsBackend()
        else:
            backend = InMemoryTracingBackend()

        _tracer = StanceTracer(backend=backend)
    return _tracer


def configure_tracing(backend: TracingBackend) -> StanceTracer:
    """
    Configure the global tracer instance.

    Args:
        backend: Tracing backend to use

    Returns:
        Configured StanceTracer instance
    """
    global _tracer
    _tracer = StanceTracer(backend=backend)
    return _tracer
