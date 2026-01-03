"""
CLI commands for Observability module.

Provides command-line interface for logging, metrics, and tracing:
- Logging configuration and log level management
- Metrics collection and viewing
- Tracing configuration and span inspection
- Observability backends status
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta
from typing import Any


def add_observability_parser(subparsers: Any) -> None:
    """Add observability parser to CLI subparsers."""
    obs_parser = subparsers.add_parser(
        "observability",
        help="Logging, metrics, and tracing management",
        description="Configure and monitor observability features",
    )

    obs_subparsers = obs_parser.add_subparsers(
        dest="observability_action",
        help="Observability action to perform",
    )

    # logging - Configure logging
    logging_parser = obs_subparsers.add_parser(
        "logging",
        help="Configure logging settings",
    )
    logging_parser.add_argument(
        "--level",
        choices=["debug", "info", "warning", "error", "critical"],
        help="Set log level",
    )
    logging_parser.add_argument(
        "--log-format",
        choices=["human", "json"],
        dest="log_format",
        help="Set log output format",
    )
    logging_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # metrics - View metrics
    metrics_parser = obs_subparsers.add_parser(
        "metrics",
        help="View collected metrics",
    )
    metrics_parser.add_argument(
        "--name",
        help="Filter by metric name",
    )
    metrics_parser.add_argument(
        "--minutes",
        type=int,
        default=60,
        help="Show metrics from last N minutes (default: 60)",
    )
    metrics_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of metrics to show (default: 50)",
    )
    metrics_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # traces - View traces
    traces_parser = obs_subparsers.add_parser(
        "traces",
        help="View collected traces",
    )
    traces_parser.add_argument(
        "--trace-id",
        dest="trace_id",
        help="Show specific trace by ID",
    )
    traces_parser.add_argument(
        "--name",
        help="Filter by span name",
    )
    traces_parser.add_argument(
        "--minutes",
        type=int,
        default=60,
        help="Show traces from last N minutes (default: 60)",
    )
    traces_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of spans to show (default: 20)",
    )
    traces_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # backends - List available backends
    backends_parser = obs_subparsers.add_parser(
        "backends",
        help="List available observability backends",
    )
    backends_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # metric-types - List metric types
    metric_types_parser = obs_subparsers.add_parser(
        "metric-types",
        help="List available metric types",
    )
    metric_types_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # log-levels - List log levels
    log_levels_parser = obs_subparsers.add_parser(
        "log-levels",
        help="List available log levels",
    )
    log_levels_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # span-statuses - List span statuses
    span_statuses_parser = obs_subparsers.add_parser(
        "span-statuses",
        help="List available span statuses",
    )
    span_statuses_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # log-formats - List log formats
    log_formats_parser = obs_subparsers.add_parser(
        "log-formats",
        help="List available log formats",
    )
    log_formats_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # stats - Show observability statistics
    stats_parser = obs_subparsers.add_parser(
        "stats",
        help="Show observability statistics",
    )
    stats_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # status - Show observability module status
    status_parser = obs_subparsers.add_parser(
        "status",
        help="Show observability module status",
    )
    status_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # summary - Get comprehensive observability summary
    summary_parser = obs_subparsers.add_parser(
        "summary",
        help="Get comprehensive observability summary",
    )
    summary_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )


def cmd_observability(args: argparse.Namespace) -> int:
    """Handle observability commands."""
    action = getattr(args, "observability_action", None)

    if not action:
        print("No observability action specified. Use 'stance observability --help' for options.")
        return 1

    handlers = {
        "logging": _handle_logging,
        "metrics": _handle_metrics,
        "traces": _handle_traces,
        "backends": _handle_backends,
        "metric-types": _handle_metric_types,
        "log-levels": _handle_log_levels,
        "span-statuses": _handle_span_statuses,
        "log-formats": _handle_log_formats,
        "stats": _handle_stats,
        "status": _handle_status,
        "summary": _handle_summary,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Unknown action: {action}")
    return 1


def _handle_logging(args: argparse.Namespace) -> int:
    """Handle logging command."""
    import os
    from stance.observability import configure_logging

    level = getattr(args, "level", None)
    log_format = getattr(args, "log_format", None)

    # Get current settings
    current_level = os.getenv("STANCE_LOG_LEVEL", "INFO")
    current_format = os.getenv("STANCE_LOG_FORMAT", "human")

    # If setting new values
    if level or log_format:
        new_level = level.upper() if level else current_level
        new_format = log_format if log_format else current_format

        configure_logging(level=new_level, format=new_format)

        if args.format == "json":
            result = {
                "action": "updated",
                "level": new_level,
                "log_format": new_format,
            }
            print(json.dumps(result, indent=2))
        else:
            print("\nLogging Configuration Updated")
            print("=" * 40)
            print(f"Log Level: {new_level}")
            print(f"Log Format: {new_format}")
    else:
        # Just show current settings
        if args.format == "json":
            result = {
                "level": current_level,
                "log_format": current_format,
            }
            print(json.dumps(result, indent=2))
        else:
            print("\nLogging Configuration")
            print("=" * 40)
            print(f"Log Level: {current_level}")
            print(f"Log Format: {current_format}")

    return 0


def _handle_metrics(args: argparse.Namespace) -> int:
    """Handle metrics command."""
    from stance.observability import get_metrics, InMemoryMetricsBackend

    metrics_instance = get_metrics()
    backend = metrics_instance.backend

    # Only InMemoryMetricsBackend supports querying
    if not isinstance(backend, InMemoryMetricsBackend):
        if args.format == "json":
            print(json.dumps({
                "error": "Metrics backend does not support querying",
                "backend_type": type(backend).__name__,
            }))
        else:
            print("Current metrics backend does not support querying.")
            print(f"Backend type: {type(backend).__name__}")
        return 0

    # Filter metrics
    since = datetime.utcnow() - timedelta(minutes=args.minutes)
    name_filter = getattr(args, "name", None)
    metrics = backend.get_metrics(name=name_filter, since=since)

    # Apply limit
    metrics = metrics[:args.limit]

    if args.format == "json":
        result = {
            "total": len(metrics),
            "filter": {
                "name": name_filter,
                "minutes": args.minutes,
            },
            "metrics": [m.to_dict() for m in metrics],
        }
        print(json.dumps(result, indent=2))
    else:
        print(f"\nMetrics (last {args.minutes} minutes)")
        print("=" * 80)
        if not metrics:
            print("No metrics found.")
        else:
            print(f"{'Name':<30} {'Value':<12} {'Type':<12} {'Timestamp':<20}")
            print("-" * 80)
            for m in metrics:
                ts = m.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                print(f"{m.name:<30} {m.value:<12.2f} {m.metric_type.value:<12} {ts:<20}")

    return 0


def _handle_traces(args: argparse.Namespace) -> int:
    """Handle traces command."""
    from stance.observability import get_tracer, InMemoryTracingBackend

    tracer = get_tracer()
    backend = tracer.backend

    # Only InMemoryTracingBackend supports querying
    if not isinstance(backend, InMemoryTracingBackend):
        if args.format == "json":
            print(json.dumps({
                "error": "Tracing backend does not support querying",
                "backend_type": type(backend).__name__,
            }))
        else:
            print("Current tracing backend does not support querying.")
            print(f"Backend type: {type(backend).__name__}")
        return 0

    trace_id = getattr(args, "trace_id", None)

    if trace_id:
        # Show specific trace
        spans = backend.get_trace(trace_id)
        if args.format == "json":
            result = {
                "trace_id": trace_id,
                "span_count": len(spans),
                "spans": [s.to_dict() for s in spans],
            }
            print(json.dumps(result, indent=2))
        else:
            print(f"\nTrace: {trace_id}")
            print("=" * 80)
            if not spans:
                print("No spans found.")
            else:
                for s in spans:
                    duration = f"{s.duration_ms:.2f}ms" if s.duration_ms else "N/A"
                    print(f"\n  Span: {s.name}")
                    print(f"    ID: {s.context.span_id}")
                    print(f"    Parent: {s.context.parent_span_id or 'None (root)'}")
                    print(f"    Status: {s.status.value}")
                    print(f"    Duration: {duration}")
                    if s.attributes:
                        print(f"    Attributes: {s.attributes}")
    else:
        # List recent spans
        since = datetime.utcnow() - timedelta(minutes=args.minutes)
        name_filter = getattr(args, "name", None)
        spans = backend.get_spans(name=name_filter, since=since)
        spans = spans[:args.limit]

        if args.format == "json":
            result = {
                "total": len(spans),
                "filter": {
                    "name": name_filter,
                    "minutes": args.minutes,
                },
                "spans": [s.to_dict() for s in spans],
            }
            print(json.dumps(result, indent=2))
        else:
            print(f"\nSpans (last {args.minutes} minutes)")
            print("=" * 80)
            if not spans:
                print("No spans found.")
            else:
                print(f"{'Name':<30} {'Status':<10} {'Duration':<12} {'Trace ID':<20}")
                print("-" * 80)
                for s in spans:
                    duration = f"{s.duration_ms:.2f}ms" if s.duration_ms else "N/A"
                    trace_short = s.context.trace_id[:16] + "..."
                    print(f"{s.name:<30} {s.status.value:<10} {duration:<12} {trace_short:<20}")

    return 0


def _handle_backends(args: argparse.Namespace) -> int:
    """Handle backends command."""
    backends = [
        {
            "name": "InMemoryMetricsBackend",
            "type": "metrics",
            "cloud": "local",
            "description": "In-memory metrics for testing and development",
            "supports_query": True,
        },
        {
            "name": "CloudWatchMetricsBackend",
            "type": "metrics",
            "cloud": "aws",
            "description": "AWS CloudWatch metrics for production monitoring",
            "supports_query": False,
        },
        {
            "name": "InMemoryTracingBackend",
            "type": "tracing",
            "cloud": "local",
            "description": "In-memory tracing for testing and development",
            "supports_query": True,
        },
        {
            "name": "XRayTracingBackend",
            "type": "tracing",
            "cloud": "aws",
            "description": "AWS X-Ray for distributed tracing",
            "supports_query": False,
        },
        {
            "name": "CloudTraceBackend",
            "type": "tracing",
            "cloud": "gcp",
            "description": "Google Cloud Trace for distributed tracing",
            "supports_query": False,
        },
        {
            "name": "ApplicationInsightsBackend",
            "type": "tracing",
            "cloud": "azure",
            "description": "Azure Application Insights for distributed tracing",
            "supports_query": False,
        },
    ]

    if args.format == "json":
        print(json.dumps({"total": len(backends), "backends": backends}, indent=2))
    else:
        print("\nObservability Backends")
        print("=" * 80)
        print(f"{'Name':<30} {'Type':<10} {'Cloud':<8} {'Queryable':<10}")
        print("-" * 80)
        for b in backends:
            queryable = "Yes" if b["supports_query"] else "No"
            print(f"{b['name']:<30} {b['type']:<10} {b['cloud']:<8} {queryable:<10}")

    return 0


def _handle_metric_types(args: argparse.Namespace) -> int:
    """Handle metric-types command."""
    metric_types = [
        {
            "type": "counter",
            "description": "Monotonically increasing value",
            "use_case": "Request counts, errors, completed operations",
            "reset": False,
        },
        {
            "type": "gauge",
            "description": "Value that can go up or down",
            "use_case": "Current connections, queue size, resource usage",
            "reset": True,
        },
        {
            "type": "histogram",
            "description": "Distribution of values",
            "use_case": "Request size distribution, response time buckets",
            "reset": True,
        },
        {
            "type": "timer",
            "description": "Duration measurements",
            "use_case": "Operation duration, latency tracking",
            "reset": True,
        },
    ]

    if args.format == "json":
        print(json.dumps({"total": len(metric_types), "metric_types": metric_types}, indent=2))
    else:
        print("\nMetric Types")
        print("=" * 60)
        for mt in metric_types:
            print(f"\n{mt['type'].upper()}")
            print(f"  {mt['description']}")
            print(f"  Use Case: {mt['use_case']}")
            print(f"  Resets: {'Yes' if mt['reset'] else 'No'}")

    return 0


def _handle_log_levels(args: argparse.Namespace) -> int:
    """Handle log-levels command."""
    log_levels = [
        {
            "level": "debug",
            "priority": 10,
            "description": "Detailed information for debugging",
            "use_case": "Development and troubleshooting",
        },
        {
            "level": "info",
            "priority": 20,
            "description": "General operational information",
            "use_case": "Normal operation tracking",
        },
        {
            "level": "warning",
            "priority": 30,
            "description": "Indication of potential issues",
            "use_case": "Recoverable errors, deprecation warnings",
        },
        {
            "level": "error",
            "priority": 40,
            "description": "Error conditions that need attention",
            "use_case": "Failed operations, exceptions",
        },
        {
            "level": "critical",
            "priority": 50,
            "description": "Critical failures requiring immediate action",
            "use_case": "System failures, data loss risks",
        },
    ]

    if args.format == "json":
        print(json.dumps({"total": len(log_levels), "log_levels": log_levels}, indent=2))
    else:
        print("\nLog Levels")
        print("=" * 60)
        for ll in log_levels:
            print(f"\n{ll['level'].upper()} (priority: {ll['priority']})")
            print(f"  {ll['description']}")
            print(f"  Use Case: {ll['use_case']}")

    return 0


def _handle_span_statuses(args: argparse.Namespace) -> int:
    """Handle span-statuses command."""
    span_statuses = [
        {
            "status": "ok",
            "description": "Operation completed successfully",
            "indicator": "Success",
        },
        {
            "status": "error",
            "description": "Operation failed with an error",
            "indicator": "Failure",
        },
        {
            "status": "cancelled",
            "description": "Operation was cancelled",
            "indicator": "Interrupted",
        },
    ]

    if args.format == "json":
        print(json.dumps({"total": len(span_statuses), "span_statuses": span_statuses}, indent=2))
    else:
        print("\nSpan Statuses")
        print("=" * 60)
        for ss in span_statuses:
            print(f"\n{ss['status'].upper()}")
            print(f"  {ss['description']}")
            print(f"  Indicator: {ss['indicator']}")

    return 0


def _handle_log_formats(args: argparse.Namespace) -> int:
    """Handle log-formats command."""
    log_formats = [
        {
            "format": "human",
            "description": "Human-readable colored output",
            "use_case": "Local development and CLI usage",
            "features": ["ANSI colors", "Readable timestamps", "Compact format"],
        },
        {
            "format": "json",
            "description": "Structured JSON output",
            "use_case": "Production and log aggregation",
            "features": ["Machine parseable", "Full context", "Extra fields support"],
        },
    ]

    if args.format == "json":
        print(json.dumps({"total": len(log_formats), "log_formats": log_formats}, indent=2))
    else:
        print("\nLog Formats")
        print("=" * 60)
        for lf in log_formats:
            print(f"\n{lf['format'].upper()}")
            print(f"  {lf['description']}")
            print(f"  Use Case: {lf['use_case']}")
            print(f"  Features: {', '.join(lf['features'])}")

    return 0


def _handle_stats(args: argparse.Namespace) -> int:
    """Handle stats command."""
    from stance.observability import get_metrics, get_tracer, InMemoryMetricsBackend, InMemoryTracingBackend

    metrics_instance = get_metrics()
    tracer = get_tracer()

    metrics_count = 0
    spans_count = 0

    if isinstance(metrics_instance.backend, InMemoryMetricsBackend):
        metrics_count = len(metrics_instance.backend.metrics)

    if isinstance(tracer.backend, InMemoryTracingBackend):
        spans_count = len(tracer.backend.spans)

    stats = {
        "metrics_backend": type(metrics_instance.backend).__name__,
        "tracing_backend": type(tracer.backend).__name__,
        "metrics_count": metrics_count,
        "spans_count": spans_count,
        "log_levels": 5,
        "metric_types": 4,
        "span_statuses": 3,
        "log_formats": 2,
        "tracing_backends_available": 4,
        "metrics_backends_available": 2,
    }

    if args.format == "json":
        print(json.dumps(stats, indent=2))
    else:
        print("\nObservability Statistics")
        print("=" * 50)
        print(f"Metrics Backend: {stats['metrics_backend']}")
        print(f"Tracing Backend: {stats['tracing_backend']}")
        print(f"Metrics Collected: {stats['metrics_count']}")
        print(f"Spans Collected: {stats['spans_count']}")
        print(f"\nCapabilities:")
        print(f"  Log Levels: {stats['log_levels']}")
        print(f"  Metric Types: {stats['metric_types']}")
        print(f"  Span Statuses: {stats['span_statuses']}")
        print(f"  Log Formats: {stats['log_formats']}")
        print(f"  Tracing Backends: {stats['tracing_backends_available']}")
        print(f"  Metrics Backends: {stats['metrics_backends_available']}")

    return 0


def _handle_status(args: argparse.Namespace) -> int:
    """Handle status command."""
    import os
    from stance.observability import get_metrics, get_tracer

    metrics_instance = get_metrics()
    tracer = get_tracer()

    status = {
        "module": "observability",
        "status": "operational",
        "components": {
            "StanceLogger": "available",
            "StructuredFormatter": "available",
            "HumanReadableFormatter": "available",
            "StanceMetrics": "available",
            "MetricValue": "available",
            "StanceTracer": "available",
            "Span": "available",
            "SpanContext": "available",
        },
        "active_backends": {
            "metrics": type(metrics_instance.backend).__name__,
            "tracing": type(tracer.backend).__name__,
        },
        "environment": {
            "STANCE_LOG_LEVEL": os.getenv("STANCE_LOG_LEVEL", "INFO"),
            "STANCE_LOG_FORMAT": os.getenv("STANCE_LOG_FORMAT", "human"),
            "STANCE_METRICS_BACKEND": os.getenv("STANCE_METRICS_BACKEND", "memory"),
            "STANCE_TRACING_BACKEND": os.getenv("STANCE_TRACING_BACKEND", "memory"),
        },
        "capabilities": [
            "structured_logging",
            "human_readable_logging",
            "metric_counters",
            "metric_gauges",
            "metric_timers",
            "metric_histograms",
            "distributed_tracing",
            "span_attributes",
            "span_events",
            "context_propagation",
            "aws_cloudwatch_export",
            "aws_xray_export",
            "gcp_cloudtrace_export",
            "azure_appinsights_export",
        ],
    }

    if args.format == "json":
        print(json.dumps(status, indent=2))
    else:
        print("\nObservability Module Status")
        print("=" * 50)
        print(f"Module: {status['module']}")
        print(f"Status: {status['status']}")
        print(f"\nActive Backends:")
        for backend_type, backend_name in status["active_backends"].items():
            print(f"  {backend_type}: {backend_name}")
        print(f"\nEnvironment:")
        for key, value in status["environment"].items():
            print(f"  {key}: {value}")
        print(f"\nComponents:")
        for comp, state in status["components"].items():
            print(f"  {comp}: {state}")
        print(f"\nCapabilities ({len(status['capabilities'])}):")
        for cap in status["capabilities"][:8]:
            print(f"  - {cap}")
        if len(status["capabilities"]) > 8:
            print(f"  ... and {len(status['capabilities']) - 8} more")

    return 0


def _handle_summary(args: argparse.Namespace) -> int:
    """Handle summary command."""
    summary = {
        "module": "observability",
        "version": "1.0.0",
        "description": "Logging, metrics, and distributed tracing for Mantissa Stance",
        "features": [
            "Structured JSON logging for log aggregation",
            "Human-readable colored console output",
            "Metric counters, gauges, timers, and histograms",
            "CloudWatch metrics export for AWS",
            "Distributed tracing with span context propagation",
            "AWS X-Ray tracing backend",
            "GCP Cloud Trace backend",
            "Azure Application Insights backend",
            "In-memory backends for testing",
            "Environment-based configuration",
        ],
        "logging": {
            "levels": ["debug", "info", "warning", "error", "critical"],
            "formats": ["human", "json"],
            "env_vars": ["STANCE_LOG_LEVEL", "STANCE_LOG_FORMAT"],
        },
        "metrics": {
            "types": ["counter", "gauge", "histogram", "timer"],
            "backends": ["InMemoryMetricsBackend", "CloudWatchMetricsBackend"],
            "env_var": "STANCE_METRICS_BACKEND",
        },
        "tracing": {
            "statuses": ["ok", "error", "cancelled"],
            "backends": [
                "InMemoryTracingBackend",
                "XRayTracingBackend",
                "CloudTraceBackend",
                "ApplicationInsightsBackend",
            ],
            "env_var": "STANCE_TRACING_BACKEND",
        },
    }

    if args.format == "json":
        print(json.dumps(summary, indent=2))
    else:
        print("\nObservability Module Summary")
        print("=" * 60)
        print(f"Module: {summary['module']}")
        print(f"Version: {summary['version']}")
        print(f"Description: {summary['description']}")

        print(f"\nFeatures:")
        for feature in summary["features"]:
            print(f"  - {feature}")

        print(f"\nLogging:")
        print(f"  Levels: {', '.join(summary['logging']['levels'])}")
        print(f"  Formats: {', '.join(summary['logging']['formats'])}")
        print(f"  Env Vars: {', '.join(summary['logging']['env_vars'])}")

        print(f"\nMetrics:")
        print(f"  Types: {', '.join(summary['metrics']['types'])}")
        print(f"  Backends: {len(summary['metrics']['backends'])}")
        print(f"  Env Var: {summary['metrics']['env_var']}")

        print(f"\nTracing:")
        print(f"  Statuses: {', '.join(summary['tracing']['statuses'])}")
        print(f"  Backends: {len(summary['tracing']['backends'])}")
        print(f"  Env Var: {summary['tracing']['env_var']}")

    return 0
