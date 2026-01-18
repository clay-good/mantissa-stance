"""
Observability handlers for the Stance web API.

This module handles all /api/observability/* endpoints for logging,
metrics, traces, and observability backend configuration.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class ObservabilityHandler(RoutedHandler):
    """
    Handler for observability API endpoints.

    Handles:
    - Logging configuration
    - Metrics collection
    - Distributed tracing
    - Backend configuration
    """

    base_path = "/api/observability/"

    # =========================================================================
    # GET endpoints
    # =========================================================================

    @route("logging")
    def observability_logging(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Get or configure logging settings.

        Query params:
            level: Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            format: Set log format (human, structured)
        """
        level = self.get_param(params, "level", "")
        format_type = self.get_param(params, "format", "")

        current_level = os.environ.get("STANCE_LOG_LEVEL", "INFO")
        current_format = os.environ.get("STANCE_LOG_FORMAT", "human")

        if level or format_type:
            if level:
                os.environ["STANCE_LOG_LEVEL"] = level.upper()
                current_level = level.upper()
            if format_type:
                os.environ["STANCE_LOG_FORMAT"] = format_type.lower()
                current_format = format_type.lower()
            return HandlerResponse.success({
                "status": "configured",
                "level": current_level,
                "format": current_format,
            })

        return HandlerResponse.success({
            "current_level": current_level,
            "current_format": current_format,
            "available_levels": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            "available_formats": ["human", "structured"],
            "env_vars": {
                "level": "STANCE_LOG_LEVEL",
                "format": "STANCE_LOG_FORMAT",
            },
        })

    @route("metrics")
    def observability_metrics(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Get collected metrics.

        Query params:
            name: Filter by metric name
            type: Filter by metric type
            limit: Maximum metrics to return (default: 100)
        """
        name = self.get_param(params, "name", "")
        metric_type = self.get_param(params, "type", "")
        limit = self.get_param_int(params, "limit", 100)

        try:
            from stance.observability import get_metrics, InMemoryMetricsBackend

            metrics_instance = get_metrics()
            if hasattr(metrics_instance, "_backend") and isinstance(metrics_instance._backend, InMemoryMetricsBackend):
                all_metrics = metrics_instance._backend.get_metrics(name=name or None)
                filtered = []
                for m in all_metrics:
                    if metric_type and m.metric_type.value != metric_type:
                        continue
                    filtered.append(m.to_dict())
                    if len(filtered) >= limit:
                        break
                return HandlerResponse.success({
                    "total": len(filtered),
                    "limit": limit,
                    "metrics": filtered,
                })
            return HandlerResponse.success({
                "total": 0,
                "metrics": [],
                "note": "No in-memory backend available for querying",
            })
        except Exception as e:
            logger.warning(f"Error getting metrics: {e}")
            return HandlerResponse.success({
                "total": 0,
                "metrics": [],
                "note": "Metrics backend not initialized",
            })

    @route("traces")
    def observability_traces(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Get collected traces/spans.

        Query params:
            trace_id: Filter by specific trace ID
            limit: Maximum spans to return (default: 100)
        """
        trace_id = self.get_param(params, "trace_id", "")
        limit = self.get_param_int(params, "limit", 100)

        try:
            from stance.observability import get_tracer, InMemoryTracingBackend

            tracer = get_tracer()
            if hasattr(tracer, "_backend") and isinstance(tracer._backend, InMemoryTracingBackend):
                if trace_id:
                    spans = tracer._backend.get_trace(trace_id)
                    return HandlerResponse.success({
                        "trace_id": trace_id,
                        "total_spans": len(spans),
                        "spans": [s.to_dict() for s in spans],
                    })
                else:
                    all_spans = tracer._backend.get_spans(limit=limit)
                    return HandlerResponse.success({
                        "total": len(all_spans),
                        "limit": limit,
                        "spans": [s.to_dict() for s in all_spans],
                    })
            return HandlerResponse.success({
                "total": 0,
                "spans": [],
                "note": "No in-memory backend available for querying",
            })
        except Exception as e:
            logger.warning(f"Error getting traces: {e}")
            return HandlerResponse.success({
                "total": 0,
                "spans": [],
                "note": "Tracing backend not initialized",
            })

    @route("backends")
    def observability_backends(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available observability backends."""
        backends = [
            {
                "backend": "InMemoryMetricsBackend",
                "type": "metrics",
                "description": "In-memory metrics storage for development and testing",
                "cloud": "any",
            },
            {
                "backend": "CloudWatchMetricsBackend",
                "type": "metrics",
                "description": "AWS CloudWatch metrics integration",
                "cloud": "aws",
            },
            {
                "backend": "InMemoryTracingBackend",
                "type": "tracing",
                "description": "In-memory trace storage for development and testing",
                "cloud": "any",
            },
            {
                "backend": "XRayTracingBackend",
                "type": "tracing",
                "description": "AWS X-Ray distributed tracing integration",
                "cloud": "aws",
            },
            {
                "backend": "CloudTraceBackend",
                "type": "tracing",
                "description": "Google Cloud Trace integration",
                "cloud": "gcp",
            },
            {
                "backend": "ApplicationInsightsBackend",
                "type": "tracing",
                "description": "Azure Application Insights integration",
                "cloud": "azure",
            },
        ]
        return HandlerResponse.success({
            "total": len(backends),
            "backends": backends,
        })

    @route("metric-types")
    def observability_metric_types(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available metric types."""
        metric_types = [
            {
                "type": "counter",
                "description": "Monotonically increasing counter",
                "use_case": "Request counts, error counts, event totals",
            },
            {
                "type": "gauge",
                "description": "Point-in-time value that can increase or decrease",
                "use_case": "Memory usage, queue size, active connections",
            },
            {
                "type": "histogram",
                "description": "Distribution of values across buckets",
                "use_case": "Request latencies, response sizes",
            },
            {
                "type": "summary",
                "description": "Pre-calculated quantiles over time",
                "use_case": "Percentile latencies (p50, p90, p99)",
            },
        ]
        return HandlerResponse.success({
            "types": metric_types,
            "total": len(metric_types),
        })

    @route("log-levels")
    def observability_log_levels(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available log levels."""
        log_levels = [
            {"level": "DEBUG", "value": 10, "description": "Detailed debug information"},
            {"level": "INFO", "value": 20, "description": "General operational information"},
            {"level": "WARNING", "value": 30, "description": "Warning conditions"},
            {"level": "ERROR", "value": 40, "description": "Error conditions"},
            {"level": "CRITICAL", "value": 50, "description": "Critical conditions"},
        ]
        return HandlerResponse.success({
            "levels": log_levels,
            "total": len(log_levels),
            "current": os.environ.get("STANCE_LOG_LEVEL", "INFO"),
        })

    @route("span-statuses")
    def observability_span_statuses(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available span statuses."""
        span_statuses = [
            {"status": "unset", "description": "Status not set"},
            {"status": "ok", "description": "Operation completed successfully"},
            {"status": "error", "description": "Operation failed"},
        ]
        return HandlerResponse.success({
            "statuses": span_statuses,
            "total": len(span_statuses),
        })

    @route("log-formats")
    def observability_log_formats(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available log formats."""
        log_formats = [
            {"format": "human", "description": "Human-readable log format"},
            {"format": "structured", "description": "JSON structured log format"},
        ]
        return HandlerResponse.success({
            "formats": log_formats,
            "total": len(log_formats),
            "current": os.environ.get("STANCE_LOG_FORMAT", "human"),
        })

    @route("stats")
    def observability_stats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get observability statistics."""
        return HandlerResponse.success({
            "metrics_collected": 0,
            "traces_collected": 0,
            "logs_emitted": 0,
            "backends_active": 2,
        })

    @route("status")
    def observability_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get observability module status."""
        return HandlerResponse.success({
            "module": "observability",
            "version": "1.0.0",
            "status": "active",
            "logging": {
                "level": os.environ.get("STANCE_LOG_LEVEL", "INFO"),
                "format": os.environ.get("STANCE_LOG_FORMAT", "human"),
            },
            "metrics": {
                "backend": "InMemoryMetricsBackend",
                "enabled": True,
            },
            "tracing": {
                "backend": "InMemoryTracingBackend",
                "enabled": True,
            },
            "capabilities": {
                "structured_logging": True,
                "metrics_collection": True,
                "distributed_tracing": True,
                "cloud_integration": True,
            },
        })

    @route("summary")
    def observability_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get observability summary."""
        return HandlerResponse.success({
            "logging_level": os.environ.get("STANCE_LOG_LEVEL", "INFO"),
            "logging_format": os.environ.get("STANCE_LOG_FORMAT", "human"),
            "metrics_backend": "InMemoryMetricsBackend",
            "tracing_backend": "InMemoryTracingBackend",
            "metrics_count": 0,
            "traces_count": 0,
        })
