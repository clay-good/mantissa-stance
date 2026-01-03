"""
Unit tests for Reporting CLI module.

Tests the command-line interface for trend analysis and security reporting.
"""

import pytest
import argparse
import json
from unittest.mock import MagicMock, patch

from stance.cli_reporting import (
    add_reporting_parser,
    cmd_reporting,
    _handle_analyze,
    _handle_velocity,
    _handle_improvement,
    _handle_compare,
    _handle_forecast,
    _handle_directions,
    _handle_periods,
    _handle_severities,
    _handle_metrics,
    _handle_stats,
    _handle_status,
    _handle_summary,
)


class TestAddReportingParser:
    """Tests for add_reporting_parser function."""

    def test_parser_creation(self):
        """Test that parser is created correctly."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_reporting_parser(subparsers)

        # Should not raise
        args = parser.parse_args(["reporting", "status"])
        assert args.reporting_action == "status"

    def test_all_subcommands_available(self):
        """Test that all subcommands are available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_reporting_parser(subparsers)

        commands = [
            ("analyze", []),
            ("velocity", []),
            ("improvement", []),
            ("compare", []),
            ("forecast", []),
            ("directions", []),
            ("periods", []),
            ("severities", []),
            ("metrics", []),
            ("stats", []),
            ("status", []),
            ("summary", []),
        ]

        for cmd, extra_args in commands:
            args = parser.parse_args(["reporting", cmd] + extra_args)
            assert args.reporting_action == cmd


class TestCmdReporting:
    """Tests for cmd_reporting handler."""

    def test_no_action_shows_error(self, capsys):
        """Test that no action shows error."""
        args = argparse.Namespace(reporting_action=None)
        result = cmd_reporting(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "No reporting action specified" in captured.out

    def test_unknown_action_shows_error(self, capsys):
        """Test that unknown action shows error."""
        args = argparse.Namespace(reporting_action="unknown")
        result = cmd_reporting(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "Unknown action" in captured.out

    def test_valid_action_routes_correctly(self):
        """Test that valid actions route to correct handlers."""
        args = argparse.Namespace(
            reporting_action="status",
            format="json",
        )
        result = cmd_reporting(args)
        assert result == 0


class TestHandleDirections:
    """Tests for directions command handler."""

    def test_directions_table(self, capsys):
        """Test listing directions in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_directions(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Trend Directions" in captured.out
        assert "IMPROVING" in captured.out
        assert "DECLINING" in captured.out
        assert "STABLE" in captured.out
        assert "INSUFFICIENT_DATA" in captured.out

    def test_directions_json(self, capsys):
        """Test listing directions in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_directions(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "total" in data
        assert "directions" in data
        assert data["total"] == 4
        assert len(data["directions"]) == 4


class TestHandlePeriods:
    """Tests for periods command handler."""

    def test_periods_table(self, capsys):
        """Test listing periods in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_periods(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Trend Periods" in captured.out
        assert "DAILY" in captured.out
        assert "WEEKLY" in captured.out
        assert "MONTHLY" in captured.out
        assert "QUARTERLY" in captured.out

    def test_periods_json(self, capsys):
        """Test listing periods in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_periods(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["total"] == 4
        assert len(data["periods"]) == 4


class TestHandleSeverities:
    """Tests for severities command handler."""

    def test_severities_table(self, capsys):
        """Test listing severities in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_severities(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Severity Levels" in captured.out
        assert "CRITICAL" in captured.out
        assert "HIGH" in captured.out
        assert "MEDIUM" in captured.out
        assert "LOW" in captured.out
        assert "INFO" in captured.out

    def test_severities_json(self, capsys):
        """Test listing severities in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_severities(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["total"] == 5
        assert len(data["severities"]) == 5


class TestHandleMetrics:
    """Tests for metrics command handler."""

    def test_metrics_table(self, capsys):
        """Test listing metrics in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_metrics(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Available Trend Metrics" in captured.out
        assert "current_value" in captured.out
        assert "velocity" in captured.out

    def test_metrics_json(self, capsys):
        """Test listing metrics in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_metrics(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "total" in data
        assert "metrics" in data
        assert data["total"] == 10


class TestHandleStats:
    """Tests for stats command handler."""

    def test_stats_table(self, capsys):
        """Test showing stats in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_stats(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Reporting Module Statistics" in captured.out
        assert "Trend Directions" in captured.out

    def test_stats_json(self, capsys):
        """Test showing stats in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_stats(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["trend_directions"] == 4
        assert data["trend_periods"] == 4
        assert data["severity_levels"] == 5


class TestHandleStatus:
    """Tests for status command handler."""

    def test_status_table(self, capsys):
        """Test showing status in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_status(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Reporting Module Status" in captured.out
        assert "Components:" in captured.out

    def test_status_json(self, capsys):
        """Test showing status in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_status(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["module"] == "reporting"
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
        assert "Reporting Module Summary" in captured.out
        assert "Features:" in captured.out

    def test_summary_json(self, capsys):
        """Test showing summary in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_summary(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["module"] == "reporting"
        assert "features" in data
        assert "analysis_types" in data
        assert "data_requirements" in data


class TestHandleAnalyze:
    """Tests for analyze command handler."""

    def test_analyze_json(self, capsys):
        """Test analyze with JSON format."""
        args = argparse.Namespace(
            config="default",
            days=30,
            period="daily",
            format="json",
        )
        result = _handle_analyze(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        # Should contain report structure
        assert "report_id" in data
        assert "period" in data
        assert "total_findings" in data

    def test_analyze_table(self, capsys):
        """Test analyze with table format."""
        args = argparse.Namespace(
            config="default",
            days=7,
            period="daily",
            format="table",
        )
        result = _handle_analyze(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Trend Analysis Report" in captured.out


class TestHandleVelocity:
    """Tests for velocity command handler."""

    def test_velocity_json(self, capsys):
        """Test velocity with JSON format."""
        args = argparse.Namespace(
            config="default",
            days=7,
            format="json",
        )
        result = _handle_velocity(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "velocities" in data
        assert "unit" in data
        assert data["unit"] == "findings/day"

    def test_velocity_table(self, capsys):
        """Test velocity with table format."""
        args = argparse.Namespace(
            config="default",
            days=7,
            format="table",
        )
        result = _handle_velocity(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Findings Velocity" in captured.out


class TestHandleImprovement:
    """Tests for improvement command handler."""

    def test_improvement_json(self, capsys):
        """Test improvement with JSON format."""
        args = argparse.Namespace(
            config="default",
            days=30,
            format="json",
        )
        result = _handle_improvement(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "improvement_rate" in data
        assert "unit" in data
        assert data["unit"] == "percent"
        assert "direction" in data

    def test_improvement_table(self, capsys):
        """Test improvement with table format."""
        args = argparse.Namespace(
            config="default",
            days=30,
            format="table",
        )
        result = _handle_improvement(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Security Improvement Rate" in captured.out


class TestHandleCompare:
    """Tests for compare command handler."""

    def test_compare_json(self, capsys):
        """Test compare with JSON format."""
        args = argparse.Namespace(
            config="default",
            current_days=7,
            previous_days=7,
            format="json",
        )
        result = _handle_compare(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "current_period" in data
        assert "previous_period" in data
        assert "comparison" in data

    def test_compare_table(self, capsys):
        """Test compare with table format."""
        args = argparse.Namespace(
            config="default",
            current_days=7,
            previous_days=7,
            format="table",
        )
        result = _handle_compare(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Period Comparison" in captured.out


class TestHandleForecast:
    """Tests for forecast command handler."""

    def test_forecast_json(self, capsys):
        """Test forecast with JSON format."""
        args = argparse.Namespace(
            config="default",
            history_days=30,
            forecast_days=7,
            format="json",
        )
        result = _handle_forecast(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        # Expect either forecasts or error (if insufficient data)
        assert "forecasts" in data or "error" in data

    def test_forecast_table(self, capsys):
        """Test forecast with table format."""
        args = argparse.Namespace(
            config="default",
            history_days=30,
            forecast_days=7,
            format="table",
        )
        result = _handle_forecast(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Findings Forecast" in captured.out


class TestCLIRouting:
    """Tests for CLI command routing."""

    def test_all_handlers_exist(self):
        """Test that all handlers exist."""
        handlers = [
            _handle_analyze,
            _handle_velocity,
            _handle_improvement,
            _handle_compare,
            _handle_forecast,
            _handle_directions,
            _handle_periods,
            _handle_severities,
            _handle_metrics,
            _handle_stats,
            _handle_status,
            _handle_summary,
        ]

        for handler in handlers:
            assert callable(handler)

    def test_cmd_reporting_routes_to_all_handlers(self, capsys):
        """Test that cmd_reporting routes to all handlers."""
        actions = [
            ("status", {}),
            ("summary", {}),
            ("stats", {}),
            ("directions", {}),
            ("periods", {}),
            ("severities", {}),
            ("metrics", {}),
        ]

        for action, extra_args in actions:
            args = argparse.Namespace(
                reporting_action=action,
                format="json",
                **extra_args,
            )
            result = cmd_reporting(args)
            assert result == 0, f"Handler for {action} failed"


class TestReportingModuleIntegration:
    """Integration tests with actual reporting module."""

    def test_directions_structure(self, capsys):
        """Test directions have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_directions(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        for direction in data["directions"]:
            assert "direction" in direction
            assert "description" in direction
            assert "indicator" in direction
            assert "action" in direction

    def test_periods_structure(self, capsys):
        """Test periods have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_periods(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        for period in data["periods"]:
            assert "period" in period
            assert "description" in period
            assert "use_case" in period
            assert "recommended_history" in period

    def test_severities_structure(self, capsys):
        """Test severities have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_severities(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        for sev in data["severities"]:
            assert "severity" in sev
            assert "description" in sev
            assert "trend_priority" in sev
            assert "velocity_threshold" in sev

    def test_metrics_structure(self, capsys):
        """Test metrics have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_metrics(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        for metric in data["metrics"]:
            assert "metric" in metric
            assert "description" in metric
            assert "type" in metric

    def test_status_components_structure(self, capsys):
        """Test status components have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_status(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "TrendAnalyzer" in data["components"]
        assert "TrendReport" in data["components"]
        assert "TrendMetrics" in data["components"]
        assert "SeverityTrend" in data["components"]
        assert "ComplianceTrend" in data["components"]


class TestAnalysisContent:
    """Tests for analysis content."""

    def test_summary_has_analysis_types(self, capsys):
        """Test that summary includes analysis types."""
        args = argparse.Namespace(format="json")
        _handle_summary(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "analyze" in data["analysis_types"]
        assert "velocity" in data["analysis_types"]
        assert "improvement" in data["analysis_types"]
        assert "compare" in data["analysis_types"]
        assert "forecast" in data["analysis_types"]

    def test_summary_has_data_requirements(self, capsys):
        """Test that summary includes data requirements."""
        args = argparse.Namespace(format="json")
        _handle_summary(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "minimum_scans" in data["data_requirements"]
        assert "recommended_scans" in data["data_requirements"]
        assert "default_history_days" in data["data_requirements"]

    def test_stats_has_thresholds(self, capsys):
        """Test that stats includes thresholds."""
        args = argparse.Namespace(format="json")
        _handle_stats(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "change_threshold_percent" in data
        assert "critical_velocity_threshold" in data
        assert data["change_threshold_percent"] == 5.0
        assert data["critical_velocity_threshold"] == 0.5


class TestParserArguments:
    """Tests for parser argument handling."""

    def test_analyze_default_arguments(self):
        """Test analyze command with default arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_reporting_parser(subparsers)

        args = parser.parse_args(["reporting", "analyze"])
        assert args.config == "default"
        assert args.days == 30
        assert args.period == "daily"
        assert args.format == "table"

    def test_analyze_custom_arguments(self):
        """Test analyze command with custom arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_reporting_parser(subparsers)

        args = parser.parse_args([
            "reporting", "analyze",
            "--config", "test-config",
            "--days", "7",
            "--period", "weekly",
            "--format", "json",
        ])
        assert args.config == "test-config"
        assert args.days == 7
        assert args.period == "weekly"
        assert args.format == "json"

    def test_velocity_default_arguments(self):
        """Test velocity command with default arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_reporting_parser(subparsers)

        args = parser.parse_args(["reporting", "velocity"])
        assert args.config == "default"
        assert args.days == 7
        assert args.format == "table"

    def test_compare_default_arguments(self):
        """Test compare command with default arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_reporting_parser(subparsers)

        args = parser.parse_args(["reporting", "compare"])
        assert args.current_days == 7
        assert args.previous_days == 7

    def test_forecast_default_arguments(self):
        """Test forecast command with default arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_reporting_parser(subparsers)

        args = parser.parse_args(["reporting", "forecast"])
        assert args.history_days == 30
        assert args.forecast_days == 7
