"""
Unit tests for the Mantissa Stance CLI scheduling commands.

Tests CLI commands for schedule, history, and trends subcommands.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from stance.cli_scheduling import (
    cmd_schedule,
    cmd_history,
    cmd_trends,
    _get_scheduler,
    _get_history_manager,
    _get_trend_analyzer,
)


class TestScheduleCommand:
    """Tests for schedule CLI command."""

    def test_schedule_list_empty(self, capsys):
        """Test listing empty schedule."""
        args = argparse.Namespace(
            schedule_action="list",
            format="table",
        )

        with patch("stance.cli_scheduling._get_scheduler") as mock:
            mock_scheduler = MagicMock()
            mock_scheduler.get_jobs.return_value = []
            mock.return_value = mock_scheduler

            result = cmd_schedule(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "No scheduled jobs found" in captured.out

    def test_schedule_list_with_jobs(self, capsys):
        """Test listing scheduled jobs."""
        args = argparse.Namespace(
            schedule_action="list",
            format="table",
        )

        with patch("stance.cli_scheduling._get_scheduler") as mock:
            mock_scheduler = MagicMock()
            mock_job = MagicMock()
            mock_job.id = "job-123"
            mock_job.name = "Daily Scan"
            mock_job.schedule = "rate(1 day)"
            mock_job.enabled = True
            mock_job.last_run = datetime(2025, 1, 1, 12, 0, 0)
            mock_job.next_run = datetime(2025, 1, 2, 12, 0, 0)
            mock_job.run_count = 5
            mock_scheduler.get_jobs.return_value = [mock_job]
            mock.return_value = mock_scheduler

            result = cmd_schedule(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "job-123" in captured.out
        assert "Daily Scan" in captured.out

    def test_schedule_list_json_format(self, capsys):
        """Test listing jobs in JSON format."""
        args = argparse.Namespace(
            schedule_action="list",
            format="json",
        )

        with patch("stance.cli_scheduling._get_scheduler") as mock:
            mock_scheduler = MagicMock()
            mock_job = MagicMock()
            mock_job.id = "job-456"
            mock_job.name = "Weekly Scan"
            mock_job.schedule = "cron(0 0 * * 0)"
            mock_job.enabled = True
            mock_job.last_run = None
            mock_job.next_run = datetime(2025, 1, 5, 0, 0, 0)
            mock_job.run_count = 0
            mock_scheduler.get_jobs.return_value = [mock_job]
            mock.return_value = mock_scheduler

            result = cmd_schedule(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 1
        assert data[0]["id"] == "job-456"

    def test_schedule_add(self, capsys):
        """Test adding a scheduled job."""
        args = argparse.Namespace(
            schedule_action="add",
            name="Test Job",
            schedule="rate(1 hour)",
            config="default",
        )

        with patch("stance.cli_scheduling._get_scheduler") as mock_get:
            with patch("stance.cli_scheduling._save_scheduler"):
                mock_scheduler = MagicMock()
                mock_job = MagicMock()
                mock_job.id = "new-job-123"
                mock_job.name = "Test Job"
                mock_job.schedule = "rate(1 hour)"
                mock_job.next_run = datetime(2025, 1, 1, 13, 0, 0)
                mock_scheduler.add_job.return_value = mock_job
                mock_get.return_value = mock_scheduler

                result = cmd_schedule(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Created scheduled job" in captured.out
        assert "new-job-123" in captured.out

    def test_schedule_add_missing_params(self, capsys):
        """Test adding job with missing parameters."""
        args = argparse.Namespace(
            schedule_action="add",
            name=None,
            schedule=None,
            config="default",
        )

        result = cmd_schedule(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "--name and --schedule are required" in captured.out

    def test_schedule_remove(self, capsys):
        """Test removing a scheduled job."""
        args = argparse.Namespace(
            schedule_action="remove",
            job_id="job-to-remove",
        )

        with patch("stance.cli_scheduling._get_scheduler") as mock_get:
            with patch("stance.cli_scheduling._save_scheduler"):
                mock_scheduler = MagicMock()
                mock_scheduler.remove_job.return_value = True
                mock_get.return_value = mock_scheduler

                result = cmd_schedule(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Removed job" in captured.out

    def test_schedule_remove_not_found(self, capsys):
        """Test removing non-existent job."""
        args = argparse.Namespace(
            schedule_action="remove",
            job_id="non-existent",
        )

        with patch("stance.cli_scheduling._get_scheduler") as mock_get:
            mock_scheduler = MagicMock()
            mock_scheduler.remove_job.return_value = False
            mock_get.return_value = mock_scheduler

            result = cmd_schedule(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Job not found" in captured.out

    def test_schedule_enable(self, capsys):
        """Test enabling a job."""
        args = argparse.Namespace(
            schedule_action="enable",
            job_id="job-to-enable",
        )

        with patch("stance.cli_scheduling._get_scheduler") as mock_get:
            with patch("stance.cli_scheduling._save_scheduler"):
                mock_scheduler = MagicMock()
                mock_scheduler.enable_job.return_value = True
                mock_job = MagicMock()
                mock_job.next_run = datetime(2025, 1, 1, 12, 0, 0)
                mock_scheduler.get_job.return_value = mock_job
                mock_get.return_value = mock_scheduler

                result = cmd_schedule(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Enabled job" in captured.out

    def test_schedule_disable(self, capsys):
        """Test disabling a job."""
        args = argparse.Namespace(
            schedule_action="disable",
            job_id="job-to-disable",
        )

        with patch("stance.cli_scheduling._get_scheduler") as mock_get:
            with patch("stance.cli_scheduling._save_scheduler"):
                mock_scheduler = MagicMock()
                mock_scheduler.disable_job.return_value = True
                mock_get.return_value = mock_scheduler

                result = cmd_schedule(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Disabled job" in captured.out

    def test_schedule_status(self, capsys):
        """Test showing scheduler status."""
        args = argparse.Namespace(
            schedule_action="status",
            format="table",
        )

        with patch("stance.cli_scheduling._get_scheduler") as mock_get:
            mock_scheduler = MagicMock()
            mock_scheduler.get_status.return_value = {
                "running": True,
                "total_jobs": 3,
                "enabled_jobs": 2,
            }
            mock_get.return_value = mock_scheduler

            result = cmd_schedule(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Scheduler Status" in captured.out
        assert "Running: True" in captured.out


class TestHistoryCommand:
    """Tests for history CLI command."""

    def test_history_list_empty(self, capsys):
        """Test listing empty history."""
        args = argparse.Namespace(
            history_action="list",
            config="default",
            limit=20,
            format="table",
        )

        with patch("stance.cli_scheduling._get_history_manager") as mock:
            mock_manager = MagicMock()
            mock_manager.get_history.return_value = []
            mock.return_value = mock_manager

            result = cmd_history(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "No scan history found" in captured.out

    def test_history_list_with_entries(self, capsys):
        """Test listing history with entries."""
        args = argparse.Namespace(
            history_action="list",
            config="default",
            limit=20,
            format="table",
        )

        with patch("stance.cli_scheduling._get_history_manager") as mock:
            mock_manager = MagicMock()
            mock_entry = MagicMock()
            mock_entry.scan_id = "scan-123"
            mock_entry.timestamp = datetime(2025, 1, 1, 12, 0, 0)
            mock_entry.duration_seconds = 120.5
            mock_entry.assets_scanned = 100
            mock_entry.findings_total = 25
            mock_entry.findings_by_severity = {"critical": 2, "high": 5}
            mock_manager.get_history.return_value = [mock_entry]
            mock.return_value = mock_manager

            result = cmd_history(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "scan-123" in captured.out
        assert "100" in captured.out

    def test_history_show(self, capsys):
        """Test showing scan details."""
        args = argparse.Namespace(
            history_action="show",
            scan_id="scan-456",
            format="table",
        )

        with patch("stance.cli_scheduling._get_history_manager") as mock:
            mock_manager = MagicMock()
            mock_entry = MagicMock()
            mock_entry.scan_id = "scan-456"
            mock_entry.timestamp = datetime(2025, 1, 1, 12, 0, 0)
            mock_entry.config_name = "default"
            mock_entry.duration_seconds = 120.5
            mock_entry.assets_scanned = 100
            mock_entry.findings_total = 25
            mock_entry.findings_by_severity = {"critical": 2, "high": 5}
            mock_manager.get_entry.return_value = mock_entry
            mock.return_value = mock_manager

            result = cmd_history(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "scan-456" in captured.out
        assert "120.5s" in captured.out

    def test_history_show_not_found(self, capsys):
        """Test showing non-existent scan."""
        args = argparse.Namespace(
            history_action="show",
            scan_id="non-existent",
            format="table",
        )

        with patch("stance.cli_scheduling._get_history_manager") as mock:
            mock_manager = MagicMock()
            mock_manager.get_entry.return_value = None
            mock.return_value = mock_manager

            result = cmd_history(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Scan not found" in captured.out

    def test_history_compare(self, capsys):
        """Test comparing scans."""
        args = argparse.Namespace(
            history_action="compare",
            baseline="scan-1",
            current="scan-2",
            format="table",
        )

        with patch("stance.cli_scheduling._get_history_manager") as mock:
            mock_manager = MagicMock()
            mock_comparison = MagicMock()
            mock_comparison.baseline_scan_id = "scan-1"
            mock_comparison.current_scan_id = "scan-2"
            mock_comparison.new_findings = []
            mock_comparison.resolved_findings = [MagicMock()]
            mock_comparison.unchanged_findings = []
            mock_comparison.has_changes = True
            mock_comparison.improvement_ratio = 0.1
            mock_manager.compare_scans.return_value = mock_comparison
            mock.return_value = mock_manager

            result = cmd_history(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Scan Comparison" in captured.out
        assert "IMPROVING" in captured.out

    def test_history_trend(self, capsys):
        """Test showing trend analysis."""
        args = argparse.Namespace(
            history_action="trend",
            days=7,
            config="default",
            format="table",
        )

        with patch("stance.cli_scheduling._get_history_manager") as mock:
            mock_manager = MagicMock()
            mock_manager.get_trend.return_value = {
                "data_points": 5,
                "first_timestamp": "2025-01-01T00:00:00",
                "last_timestamp": "2025-01-07T00:00:00",
                "findings_trend": {
                    "start_count": 100,
                    "end_count": 80,
                    "change": -20,
                    "direction": "improving",
                },
            }
            mock.return_value = mock_manager

            result = cmd_history(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Trend Analysis" in captured.out
        assert "Data points: 5" in captured.out


class TestTrendsCommand:
    """Tests for trends CLI command."""

    def test_trends_summary(self, capsys):
        """Test showing trend summary."""
        args = argparse.Namespace(
            trends_action="summary",
            days=30,
            config="default",
            format="table",
        )

        with patch("stance.cli_scheduling._get_trend_analyzer") as mock:
            mock_analyzer = MagicMock()
            mock_report = MagicMock()
            mock_report.total_findings = MagicMock()
            mock_report.total_findings.direction.value = "improving"
            mock_report.total_findings.current_value = 80
            mock_report.total_findings.previous_value = 100
            mock_report.total_findings.change = -20
            mock_report.total_findings.change_percent = -20.0
            mock_report.total_findings.average = 90
            mock_report.total_findings.velocity = -0.67
            mock_report.scan_frequency = 1.5
            mock_report.severity_trends = {}
            mock_report.recommendations = ["Keep it up!"]
            mock_analyzer.analyze.return_value = mock_report
            mock.return_value = mock_analyzer

            result = cmd_trends(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Trend Analysis Summary" in captured.out
        assert "IMPROVING" in captured.out

    def test_trends_forecast(self, capsys):
        """Test showing forecast."""
        args = argparse.Namespace(
            trends_action="forecast",
            history_days=30,
            forecast_days=7,
            config="default",
            format="table",
        )

        with patch("stance.cli_scheduling._get_trend_analyzer") as mock:
            mock_analyzer = MagicMock()
            mock_analyzer.forecast.return_value = {
                "model": "linear_regression",
                "data_points": 30,
                "confidence": 0.85,
                "trend_direction": "improving",
                "trend_slope": -0.5,
                "current_findings": 80,
                "forecasts": [
                    {"day": 1, "projected_findings": 79},
                    {"day": 2, "projected_findings": 79},
                ],
            }
            mock.return_value = mock_analyzer

            result = cmd_trends(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Findings Forecast" in captured.out
        assert "Confidence" in captured.out

    def test_trends_velocity(self, capsys):
        """Test showing velocity."""
        args = argparse.Namespace(
            trends_action="velocity",
            days=7,
            config="default",
            format="table",
        )

        with patch("stance.cli_scheduling._get_trend_analyzer") as mock:
            mock_analyzer = MagicMock()
            mock_analyzer.get_findings_velocity.return_value = {
                "total": -2.5,
                "critical": -0.3,
                "high": -0.8,
                "medium": -1.0,
            }
            mock.return_value = mock_analyzer

            result = cmd_trends(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Findings Velocity" in captured.out
        assert "total" in captured.out
        assert "-2.50/day" in captured.out

    def test_trends_compare(self, capsys):
        """Test comparing periods."""
        args = argparse.Namespace(
            trends_action="compare",
            current_days=7,
            previous_days=7,
            config="default",
            format="table",
        )

        with patch("stance.cli_scheduling._get_trend_analyzer") as mock:
            mock_analyzer = MagicMock()
            mock_analyzer.compare_periods.return_value = {
                "current_period": {
                    "days": 7,
                    "stats": {"scans": 5, "avg_findings": 80},
                },
                "previous_period": {
                    "days": 7,
                    "stats": {"scans": 5, "avg_findings": 100},
                },
                "comparison": {
                    "avg_findings_change": -20.0,
                    "direction": "improving",
                },
            }
            mock.return_value = mock_analyzer

            result = cmd_trends(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Period Comparison" in captured.out
        assert "IMPROVING" in captured.out


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_get_scheduler_no_state_file(self):
        """Test getting scheduler without state file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"HOME": tmpdir}):
                scheduler = _get_scheduler()
                assert scheduler is not None

    def test_get_history_manager(self):
        """Test getting history manager."""
        manager = _get_history_manager()
        assert manager is not None

    def test_get_trend_analyzer(self):
        """Test getting trend analyzer."""
        analyzer = _get_trend_analyzer()
        assert analyzer is not None
