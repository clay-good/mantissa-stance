"""
Unit tests for Observability CLI module.

Tests the command-line interface for logging, metrics, and tracing.
"""

import pytest
import argparse
import json
from unittest.mock import MagicMock, patch

from stance.cli_observability import (
    add_observability_parser,
    cmd_observability,
    _handle_logging,
    _handle_metrics,
    _handle_traces,
    _handle_backends,
    _handle_metric_types,
    _handle_log_levels,
    _handle_span_statuses,
    _handle_log_formats,
    _handle_stats,
    _handle_status,
    _handle_summary,
)


class TestAddObservabilityParser:
    """Tests for add_observability_parser function."""

    def test_parser_creation(self):
        """Test that parser is created correctly."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_observability_parser(subparsers)

        # Should not raise
        args = parser.parse_args(["observability", "status"])
        assert args.observability_action == "status"

    def test_all_subcommands_available(self):
        """Test that all subcommands are available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_observability_parser(subparsers)

        commands = [
            ("logging", []),
            ("metrics", []),
            ("traces", []),
            ("backends", []),
            ("metric-types", []),
            ("log-levels", []),
            ("span-statuses", []),
            ("log-formats", []),
            ("stats", []),
            ("status", []),
            ("summary", []),
        ]

        for cmd, extra_args in commands:
            args = parser.parse_args(["observability", cmd] + extra_args)
            assert args.observability_action == cmd


class TestCmdObservability:
    """Tests for cmd_observability handler."""

    def test_no_action_shows_error(self, capsys):
        """Test that no action shows error."""
        args = argparse.Namespace(observability_action=None)
        result = cmd_observability(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "No observability action specified" in captured.out

    def test_unknown_action_shows_error(self, capsys):
        """Test that unknown action shows error."""
        args = argparse.Namespace(observability_action="unknown")
        result = cmd_observability(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "Unknown action" in captured.out

    def test_valid_action_routes_correctly(self):
        """Test that valid actions route to correct handlers."""
        args = argparse.Namespace(
            observability_action="status",
            format="json",
        )
        result = cmd_observability(args)
        assert result == 0


class TestHandleBackends:
    """Tests for backends command handler."""

    def test_backends_table(self, capsys):
        """Test listing backends in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_backends(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Observability Backends" in captured.out
        assert "InMemoryMetricsBackend" in captured.out
        assert "CloudWatchMetricsBackend" in captured.out
        assert "XRayTracingBackend" in captured.out

    def test_backends_json(self, capsys):
        """Test listing backends in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_backends(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "total" in data
        assert "backends" in data
        assert data["total"] == 6
        assert len(data["backends"]) == 6


class TestHandleMetricTypes:
    """Tests for metric-types command handler."""

    def test_metric_types_table(self, capsys):
        """Test listing metric types in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_metric_types(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Metric Types" in captured.out
        assert "COUNTER" in captured.out
        assert "GAUGE" in captured.out
        assert "HISTOGRAM" in captured.out
        assert "TIMER" in captured.out

    def test_metric_types_json(self, capsys):
        """Test listing metric types in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_metric_types(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["total"] == 4
        assert len(data["metric_types"]) == 4


class TestHandleLogLevels:
    """Tests for log-levels command handler."""

    def test_log_levels_table(self, capsys):
        """Test listing log levels in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_log_levels(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Log Levels" in captured.out
        assert "DEBUG" in captured.out
        assert "INFO" in captured.out
        assert "WARNING" in captured.out
        assert "ERROR" in captured.out
        assert "CRITICAL" in captured.out

    def test_log_levels_json(self, capsys):
        """Test listing log levels in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_log_levels(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["total"] == 5
        assert len(data["log_levels"]) == 5


class TestHandleSpanStatuses:
    """Tests for span-statuses command handler."""

    def test_span_statuses_table(self, capsys):
        """Test listing span statuses in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_span_statuses(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Span Statuses" in captured.out
        assert "OK" in captured.out
        assert "ERROR" in captured.out
        assert "CANCELLED" in captured.out

    def test_span_statuses_json(self, capsys):
        """Test listing span statuses in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_span_statuses(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["total"] == 3
        assert len(data["span_statuses"]) == 3


class TestHandleLogFormats:
    """Tests for log-formats command handler."""

    def test_log_formats_table(self, capsys):
        """Test listing log formats in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_log_formats(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Log Formats" in captured.out
        assert "HUMAN" in captured.out
        assert "JSON" in captured.out

    def test_log_formats_json(self, capsys):
        """Test listing log formats in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_log_formats(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["total"] == 2
        assert len(data["log_formats"]) == 2


class TestHandleStats:
    """Tests for stats command handler."""

    def test_stats_table(self, capsys):
        """Test showing stats in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_stats(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Observability Statistics" in captured.out
        assert "Metrics Backend" in captured.out

    def test_stats_json(self, capsys):
        """Test showing stats in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_stats(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["log_levels"] == 5
        assert data["metric_types"] == 4
        assert data["span_statuses"] == 3


class TestHandleStatus:
    """Tests for status command handler."""

    def test_status_table(self, capsys):
        """Test showing status in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_status(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Observability Module Status" in captured.out
        assert "Components:" in captured.out

    def test_status_json(self, capsys):
        """Test showing status in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_status(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["module"] == "observability"
        assert "status" in data
        assert "components" in data
        assert "capabilities" in data


class TestHandleSummary:
    """Tests for summary command handler."""

    def test_summary_table(self, capsys):
        """Test showing summary in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_summary(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Observability Module Summary" in captured.out
        assert "Features:" in captured.out

    def test_summary_json(self, capsys):
        """Test showing summary in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_summary(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["module"] == "observability"
        assert "features" in data
        assert "logging" in data
        assert "metrics" in data
        assert "tracing" in data


class TestHandleLogging:
    """Tests for logging command handler."""

    def test_logging_show_config(self, capsys):
        """Test showing logging configuration."""
        args = argparse.Namespace(
            level=None,
            log_format=None,
            format="json",
        )
        result = _handle_logging(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "level" in data
        assert "log_format" in data

    def test_logging_table_format(self, capsys):
        """Test logging in table format."""
        args = argparse.Namespace(
            level=None,
            log_format=None,
            format="table",
        )
        result = _handle_logging(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Logging Configuration" in captured.out


class TestHandleMetrics:
    """Tests for metrics command handler."""

    def test_metrics_json(self, capsys):
        """Test metrics with JSON format."""
        args = argparse.Namespace(
            name=None,
            minutes=60,
            limit=100,
            format="json",
        )
        result = _handle_metrics(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "total" in data or "error" in data or "backend_type" in data

    def test_metrics_table(self, capsys):
        """Test metrics with table format."""
        args = argparse.Namespace(
            name=None,
            minutes=60,
            limit=100,
            format="table",
        )
        result = _handle_metrics(args)
        assert result == 0


class TestHandleTraces:
    """Tests for traces command handler."""

    def test_traces_json(self, capsys):
        """Test traces with JSON format."""
        args = argparse.Namespace(
            trace_id=None,
            name=None,
            minutes=60,
            limit=100,
            format="json",
        )
        result = _handle_traces(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "total" in data or "error" in data or "backend_type" in data

    def test_traces_table(self, capsys):
        """Test traces with table format."""
        args = argparse.Namespace(
            trace_id=None,
            name=None,
            minutes=60,
            limit=100,
            format="table",
        )
        result = _handle_traces(args)
        assert result == 0


class TestCLIRouting:
    """Tests for CLI command routing."""

    def test_all_handlers_exist(self):
        """Test that all handlers exist."""
        handlers = [
            _handle_logging,
            _handle_metrics,
            _handle_traces,
            _handle_backends,
            _handle_metric_types,
            _handle_log_levels,
            _handle_span_statuses,
            _handle_log_formats,
            _handle_stats,
            _handle_status,
            _handle_summary,
        ]

        for handler in handlers:
            assert callable(handler)

    def test_cmd_observability_routes_to_all_handlers(self, capsys):
        """Test that cmd_observability routes to all handlers."""
        actions = [
            ("status", {}),
            ("summary", {}),
            ("stats", {}),
            ("backends", {}),
            ("metric-types", {}),
            ("log-levels", {}),
            ("span-statuses", {}),
            ("log-formats", {}),
        ]

        for action, extra_args in actions:
            args = argparse.Namespace(
                observability_action=action,
                format="json",
                **extra_args,
            )
            result = cmd_observability(args)
            assert result == 0, f"Handler for {action} failed"


class TestObservabilityModuleIntegration:
    """Integration tests with actual observability module."""

    def test_backends_structure(self, capsys):
        """Test backends have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_backends(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        for backend in data["backends"]:
            assert "name" in backend
            assert "type" in backend
            assert "description" in backend
            assert "cloud" in backend

    def test_metric_types_structure(self, capsys):
        """Test metric types have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_metric_types(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        for mt in data["metric_types"]:
            assert "type" in mt
            assert "description" in mt
            assert "use_case" in mt

    def test_log_levels_structure(self, capsys):
        """Test log levels have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_log_levels(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        for level in data["log_levels"]:
            assert "level" in level
            assert "description" in level
            assert "use_case" in level

    def test_span_statuses_structure(self, capsys):
        """Test span statuses have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_span_statuses(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        for status in data["span_statuses"]:
            assert "status" in status
            assert "description" in status
            assert "indicator" in status

    def test_log_formats_structure(self, capsys):
        """Test log formats have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_log_formats(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        for fmt in data["log_formats"]:
            assert "format" in fmt
            assert "description" in fmt
            assert "use_case" in fmt
            assert "features" in fmt

    def test_status_components_structure(self, capsys):
        """Test status components have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_status(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "StanceLogger" in data["components"]
        assert "StanceMetrics" in data["components"]
        assert "StanceTracer" in data["components"]


class TestSummaryContent:
    """Tests for summary content."""

    def test_summary_has_logging_info(self, capsys):
        """Test that summary includes logging info."""
        args = argparse.Namespace(format="json")
        _handle_summary(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "logging" in data
        assert "levels" in data["logging"]
        assert "formats" in data["logging"]

    def test_summary_has_metrics_info(self, capsys):
        """Test that summary includes metrics info."""
        args = argparse.Namespace(format="json")
        _handle_summary(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "metrics" in data
        assert "types" in data["metrics"]
        assert "backends" in data["metrics"]

    def test_summary_has_tracing_info(self, capsys):
        """Test that summary includes tracing info."""
        args = argparse.Namespace(format="json")
        _handle_summary(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "tracing" in data
        assert "statuses" in data["tracing"]
        assert "backends" in data["tracing"]

    def test_stats_has_backend_info(self, capsys):
        """Test that stats includes backend info."""
        args = argparse.Namespace(format="json")
        _handle_stats(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "metrics_backend" in data
        assert "tracing_backend" in data


class TestParserArguments:
    """Tests for parser argument handling."""

    def test_logging_default_arguments(self):
        """Test logging command with default arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_observability_parser(subparsers)

        args = parser.parse_args(["observability", "logging"])
        assert args.level is None
        assert args.log_format is None
        assert args.format == "table"

    def test_logging_custom_arguments(self):
        """Test logging command with custom arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_observability_parser(subparsers)

        args = parser.parse_args([
            "observability", "logging",
            "--level", "debug",
            "--log-format", "json",
            "--format", "json",
        ])
        assert args.level == "debug"
        assert args.log_format == "json"
        assert args.format == "json"

    def test_metrics_default_arguments(self):
        """Test metrics command with default arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_observability_parser(subparsers)

        args = parser.parse_args(["observability", "metrics"])
        assert args.name is None
        assert args.minutes == 60
        assert args.limit == 50
        assert args.format == "table"

    def test_metrics_custom_arguments(self):
        """Test metrics command with custom arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_observability_parser(subparsers)

        args = parser.parse_args([
            "observability", "metrics",
            "--name", "scan_duration",
            "--minutes", "30",
            "--limit", "25",
            "--format", "json",
        ])
        assert args.name == "scan_duration"
        assert args.minutes == 30
        assert args.limit == 25
        assert args.format == "json"

    def test_traces_default_arguments(self):
        """Test traces command with default arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_observability_parser(subparsers)

        args = parser.parse_args(["observability", "traces"])
        assert args.trace_id is None
        assert args.minutes == 60
        assert args.limit == 20
        assert args.format == "table"

    def test_traces_custom_arguments(self):
        """Test traces command with custom arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_observability_parser(subparsers)

        args = parser.parse_args([
            "observability", "traces",
            "--trace-id", "abc123",
            "--minutes", "30",
            "--limit", "10",
            "--format", "json",
        ])
        assert args.trace_id == "abc123"
        assert args.minutes == 30
        assert args.limit == 10
        assert args.format == "json"


class TestBackendsContent:
    """Tests for backends content."""

    def test_backends_include_metrics(self, capsys):
        """Test that backends include metrics backends."""
        args = argparse.Namespace(format="json")
        _handle_backends(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        backend_names = [b["name"] for b in data["backends"]]
        assert "InMemoryMetricsBackend" in backend_names
        assert "CloudWatchMetricsBackend" in backend_names

    def test_backends_include_tracing(self, capsys):
        """Test that backends include tracing backends."""
        args = argparse.Namespace(format="json")
        _handle_backends(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        backend_names = [b["name"] for b in data["backends"]]
        assert "InMemoryTracingBackend" in backend_names
        assert "XRayTracingBackend" in backend_names
        assert "CloudTraceBackend" in backend_names
        assert "ApplicationInsightsBackend" in backend_names

    def test_backends_have_cloud_providers(self, capsys):
        """Test that backends have cloud provider info."""
        args = argparse.Namespace(format="json")
        _handle_backends(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        clouds = set(b["cloud"] for b in data["backends"])
        assert "aws" in clouds
        assert "gcp" in clouds
        assert "azure" in clouds
        assert "local" in clouds


class TestCapabilities:
    """Tests for capabilities content."""

    def test_status_has_logging_capabilities(self, capsys):
        """Test that status includes logging capabilities."""
        args = argparse.Namespace(format="json")
        _handle_status(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "structured_logging" in data["capabilities"]
        assert "human_readable_logging" in data["capabilities"]

    def test_status_has_metrics_capabilities(self, capsys):
        """Test that status includes metrics capabilities."""
        args = argparse.Namespace(format="json")
        _handle_status(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "metric_counters" in data["capabilities"]
        assert "metric_gauges" in data["capabilities"]

    def test_status_has_tracing_capabilities(self, capsys):
        """Test that status includes tracing capabilities."""
        args = argparse.Namespace(format="json")
        _handle_status(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "distributed_tracing" in data["capabilities"]
        assert "context_propagation" in data["capabilities"]
