"""
Unit tests for Web API scheduling endpoints.

Tests the REST API endpoints for scan scheduling, job management,
scan history, and trend analysis.
"""

import pytest
from unittest.mock import MagicMock

from stance.web.server import StanceRequestHandler


@pytest.fixture
def handler():
    """Create a mock request handler."""
    handler = MagicMock(spec=StanceRequestHandler)
    handler.storage = None

    # Copy the actual methods to the mock
    handler._scheduling_jobs = StanceRequestHandler._scheduling_jobs.__get__(handler)
    handler._scheduling_job = StanceRequestHandler._scheduling_job.__get__(handler)
    handler._scheduling_history = StanceRequestHandler._scheduling_history.__get__(handler)
    handler._scheduling_history_entry = StanceRequestHandler._scheduling_history_entry.__get__(handler)
    handler._scheduling_compare = StanceRequestHandler._scheduling_compare.__get__(handler)
    handler._scheduling_trend = StanceRequestHandler._scheduling_trend.__get__(handler)
    handler._scheduling_status = StanceRequestHandler._scheduling_status.__get__(handler)
    handler._scheduling_schedule_types = StanceRequestHandler._scheduling_schedule_types.__get__(handler)
    handler._scheduling_diff_types = StanceRequestHandler._scheduling_diff_types.__get__(handler)
    handler._scheduling_summary = StanceRequestHandler._scheduling_summary.__get__(handler)

    return handler


class TestSchedulingJobsEndpoint:
    """Tests for /api/scheduling/jobs endpoint."""

    def test_jobs_returns_list(self, handler):
        """Test that jobs returns a list."""
        result = handler._scheduling_jobs(None)
        assert "jobs" in result
        assert "total" in result
        assert isinstance(result["jobs"], list)

    def test_jobs_structure(self, handler):
        """Test job structure."""
        result = handler._scheduling_jobs(None)
        assert result["total"] == 4
        assert "enabled_count" in result

        job = result["jobs"][0]
        assert "id" in job
        assert "name" in job
        assert "schedule_type" in job
        assert "schedule_expression" in job
        assert "enabled" in job
        assert "last_run" in job
        assert "next_run" in job

    def test_jobs_enabled_only_filter(self, handler):
        """Test filtering by enabled status."""
        result = handler._scheduling_jobs({"enabled_only": ["true"]})
        assert all(j["enabled"] for j in result["jobs"])

    def test_jobs_includes_expected(self, handler):
        """Test that expected jobs are included."""
        result = handler._scheduling_jobs(None)
        names = {j["name"] for j in result["jobs"]}
        assert "Daily Security Scan" in names
        assert "Hourly Critical Check" in names


class TestSchedulingJobEndpoint:
    """Tests for /api/scheduling/job endpoint."""

    def test_job_requires_id(self, handler):
        """Test that job_id is required."""
        result = handler._scheduling_job(None)
        assert "error" in result

    def test_job_returns_details(self, handler):
        """Test that job returns details for valid ID."""
        result = handler._scheduling_job({"job_id": ["job-daily-security-scan"]})
        assert "job" in result
        assert result["job"]["id"] == "job-daily-security-scan"

    def test_job_structure(self, handler):
        """Test job detail structure."""
        result = handler._scheduling_job({"job_id": ["job-daily-security-scan"]})
        job = result["job"]
        assert "id" in job
        assert "name" in job
        assert "schedule_type" in job
        assert "schedule_expression" in job
        assert "schedule_description" in job
        assert "last_result" in job
        assert "metadata" in job

    def test_job_not_found(self, handler):
        """Test error for invalid job ID."""
        result = handler._scheduling_job({"job_id": ["invalid-job"]})
        assert "error" in result
        assert "not found" in result["error"].lower()


class TestSchedulingHistoryEndpoint:
    """Tests for /api/scheduling/history endpoint."""

    def test_history_returns_list(self, handler):
        """Test that history returns a list."""
        result = handler._scheduling_history(None)
        assert "history" in result
        assert "total" in result
        assert isinstance(result["history"], list)

    def test_history_structure(self, handler):
        """Test history entry structure."""
        result = handler._scheduling_history(None)
        assert len(result["history"]) > 0

        entry = result["history"][0]
        assert "scan_id" in entry
        assert "timestamp" in entry
        assert "config_name" in entry
        assert "duration_seconds" in entry
        assert "assets_scanned" in entry
        assert "findings_total" in entry
        assert "findings_by_severity" in entry

    def test_history_filter_by_config(self, handler):
        """Test filtering history by config name."""
        result = handler._scheduling_history({"config_name": ["default"]})
        assert all(h["config_name"] == "default" for h in result["history"])

    def test_history_limit(self, handler):
        """Test limiting history results."""
        result = handler._scheduling_history({"limit": ["2"]})
        assert len(result["history"]) <= 2


class TestSchedulingHistoryEntryEndpoint:
    """Tests for /api/scheduling/history-entry endpoint."""

    def test_entry_requires_id(self, handler):
        """Test that scan_id is required."""
        result = handler._scheduling_history_entry(None)
        assert "error" in result

    def test_entry_returns_details(self, handler):
        """Test that entry returns details for valid ID."""
        result = handler._scheduling_history_entry({"scan_id": ["scan-2024-01-15-0200"]})
        assert "entry" in result
        assert result["entry"]["scan_id"] == "scan-2024-01-15-0200"

    def test_entry_structure(self, handler):
        """Test history entry detail structure."""
        result = handler._scheduling_history_entry({"scan_id": ["scan-2024-01-15-0200"]})
        entry = result["entry"]
        assert "scan_id" in entry
        assert "timestamp" in entry
        assert "config_name" in entry
        assert "accounts_scanned" in entry
        assert "regions_scanned" in entry
        assert "collectors_used" in entry
        assert "metadata" in entry

    def test_entry_not_found(self, handler):
        """Test error for invalid scan ID."""
        result = handler._scheduling_history_entry({"scan_id": ["invalid-scan"]})
        assert "error" in result
        assert "not found" in result["error"].lower()


class TestSchedulingCompareEndpoint:
    """Tests for /api/scheduling/compare endpoint."""

    def test_compare_returns_dict(self, handler):
        """Test that compare returns a dictionary."""
        result = handler._scheduling_compare(None)
        assert "comparison" in result
        assert isinstance(result["comparison"], dict)

    def test_compare_structure(self, handler):
        """Test comparison structure."""
        result = handler._scheduling_compare(None)
        comparison = result["comparison"]
        assert "baseline_scan_id" in comparison
        assert "current_scan_id" in comparison
        assert "baseline_timestamp" in comparison
        assert "current_timestamp" in comparison
        assert "summary" in comparison
        assert "direction" in comparison

    def test_compare_summary_structure(self, handler):
        """Test comparison summary structure."""
        result = handler._scheduling_compare(None)
        summary = result["comparison"]["summary"]
        assert "total_new" in summary
        assert "total_resolved" in summary
        assert "total_unchanged" in summary
        assert "has_changes" in summary
        assert "improvement_ratio" in summary

    def test_compare_with_params(self, handler):
        """Test comparison with specific scan IDs."""
        result = handler._scheduling_compare({
            "baseline": ["scan-2024-01-14-0200"],
            "current": ["scan-2024-01-15-0200"],
        })
        assert result["comparison"]["baseline_scan_id"] == "scan-2024-01-14-0200"
        assert result["comparison"]["current_scan_id"] == "scan-2024-01-15-0200"


class TestSchedulingTrendEndpoint:
    """Tests for /api/scheduling/trend endpoint."""

    def test_trend_returns_list(self, handler):
        """Test that trend returns a list."""
        result = handler._scheduling_trend(None)
        assert "trend" in result
        assert isinstance(result["trend"], list)

    def test_trend_structure(self, handler):
        """Test trend data structure."""
        result = handler._scheduling_trend(None)
        assert "config_name" in result
        assert "days" in result
        assert "data_points" in result
        assert "summary" in result

        if result["trend"]:
            point = result["trend"][0]
            assert "timestamp" in point
            assert "scan_id" in point
            assert "findings_total" in point
            assert "critical" in point
            assert "high" in point

    def test_trend_summary_structure(self, handler):
        """Test trend summary structure."""
        result = handler._scheduling_trend(None)
        summary = result["summary"]
        assert "start_findings" in summary
        assert "end_findings" in summary
        assert "change" in summary
        assert "direction" in summary

    def test_trend_with_days_param(self, handler):
        """Test trend with custom days parameter."""
        result = handler._scheduling_trend({"days": ["3"]})
        assert result["days"] == 3


class TestSchedulingStatusEndpoint:
    """Tests for /api/scheduling/status endpoint."""

    def test_status_returns_dict(self, handler):
        """Test that status returns a dictionary."""
        result = handler._scheduling_status(None)
        assert isinstance(result, dict)

    def test_status_structure(self, handler):
        """Test status structure."""
        result = handler._scheduling_status(None)
        assert "status" in result
        assert "scheduler" in result
        assert "jobs" in result
        assert "history" in result
        assert "capabilities" in result
        assert "components" in result

    def test_status_operational(self, handler):
        """Test status is operational."""
        result = handler._scheduling_status(None)
        assert result["status"] == "operational"

    def test_status_scheduler_section(self, handler):
        """Test scheduler section in status."""
        result = handler._scheduling_status(None)
        scheduler = result["scheduler"]
        assert "running" in scheduler
        assert "check_interval" in scheduler
        assert "last_check" in scheduler

    def test_status_components(self, handler):
        """Test status includes required components."""
        result = handler._scheduling_status(None)
        components = result["components"]
        assert "ScanScheduler" in components
        assert "ScanHistoryManager" in components


class TestSchedulingScheduleTypesEndpoint:
    """Tests for /api/scheduling/schedule-types endpoint."""

    def test_schedule_types_returns_list(self, handler):
        """Test that schedule_types returns a list."""
        result = handler._scheduling_schedule_types(None)
        assert "types" in result
        assert "total" in result
        assert isinstance(result["types"], list)

    def test_schedule_types_structure(self, handler):
        """Test schedule type structure."""
        result = handler._scheduling_schedule_types(None)
        assert result["total"] == 3

        stype = result["types"][0]
        assert "value" in stype
        assert "description" in stype
        assert "examples" in stype
        assert "format" in stype

    def test_schedule_types_includes_expected(self, handler):
        """Test that expected types are included."""
        result = handler._scheduling_schedule_types(None)
        values = {t["value"] for t in result["types"]}
        assert "cron" in values
        assert "rate" in values
        assert "once" in values


class TestSchedulingDiffTypesEndpoint:
    """Tests for /api/scheduling/diff-types endpoint."""

    def test_diff_types_returns_list(self, handler):
        """Test that diff_types returns a list."""
        result = handler._scheduling_diff_types(None)
        assert "types" in result
        assert "total" in result
        assert isinstance(result["types"], list)

    def test_diff_types_structure(self, handler):
        """Test diff type structure."""
        result = handler._scheduling_diff_types(None)
        assert result["total"] == 5

        dtype = result["types"][0]
        assert "value" in dtype
        assert "description" in dtype
        assert "indicator" in dtype

    def test_diff_types_includes_expected(self, handler):
        """Test that expected diff types are included."""
        result = handler._scheduling_diff_types(None)
        values = {t["value"] for t in result["types"]}
        assert "new" in values
        assert "resolved" in values
        assert "unchanged" in values
        assert "severity_changed" in values
        assert "status_changed" in values


class TestSchedulingSummaryEndpoint:
    """Tests for /api/scheduling/summary endpoint."""

    def test_summary_returns_dict(self, handler):
        """Test that summary returns a dictionary."""
        result = handler._scheduling_summary(None)
        assert "summary" in result
        assert isinstance(result["summary"], dict)

    def test_summary_structure(self, handler):
        """Test summary structure."""
        result = handler._scheduling_summary(None)
        summary = result["summary"]
        assert "scheduler" in summary
        assert "history" in summary
        assert "trends" in summary
        assert "configs" in summary

    def test_summary_scheduler_section(self, handler):
        """Test scheduler section in summary."""
        result = handler._scheduling_summary(None)
        scheduler = result["summary"]["scheduler"]
        assert "running" in scheduler
        assert "total_jobs" in scheduler
        assert "enabled_jobs" in scheduler
        assert "next_job" in scheduler

    def test_summary_history_section(self, handler):
        """Test history section in summary."""
        result = handler._scheduling_summary(None)
        history = result["summary"]["history"]
        assert "total_scans" in history
        assert "scans_today" in history
        assert "scans_this_week" in history
        assert "latest_scan" in history

    def test_summary_trends_section(self, handler):
        """Test trends section in summary."""
        result = handler._scheduling_summary(None)
        trends = result["summary"]["trends"]
        assert "direction" in trends
        assert "findings_velocity" in trends
        assert "improvement_rate" in trends


class TestSchedulingEndpointRouting:
    """Tests for scheduling endpoint routing in do_GET."""

    def test_get_endpoints_exist(self):
        """Test that all scheduling GET endpoints are routed."""
        endpoints = [
            "/api/scheduling/jobs",
            "/api/scheduling/job",
            "/api/scheduling/history",
            "/api/scheduling/history-entry",
            "/api/scheduling/compare",
            "/api/scheduling/trend",
            "/api/scheduling/status",
            "/api/scheduling/schedule-types",
            "/api/scheduling/diff-types",
            "/api/scheduling/summary",
        ]

        for endpoint in endpoints:
            # Handle hyphenated names
            method_name = "_scheduling_" + endpoint.split("/")[-1].replace("-", "_")
            assert hasattr(StanceRequestHandler, method_name), f"Method {method_name} not found"
