"""
Unit tests for Web API automation endpoints.

Tests the REST API endpoints for notification automation,
configuration, and notification history.
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
    handler._automation_config = StanceRequestHandler._automation_config.__get__(handler)
    handler._automation_types = StanceRequestHandler._automation_types.__get__(handler)
    handler._automation_history = StanceRequestHandler._automation_history.__get__(handler)
    handler._automation_thresholds = StanceRequestHandler._automation_thresholds.__get__(handler)
    handler._automation_triggers = StanceRequestHandler._automation_triggers.__get__(handler)
    handler._automation_callbacks = StanceRequestHandler._automation_callbacks.__get__(handler)
    handler._automation_severities = StanceRequestHandler._automation_severities.__get__(handler)
    handler._automation_status = StanceRequestHandler._automation_status.__get__(handler)
    handler._automation_test = StanceRequestHandler._automation_test.__get__(handler)
    handler._automation_summary = StanceRequestHandler._automation_summary.__get__(handler)
    handler._automation_workflows = StanceRequestHandler._automation_workflows.__get__(handler)
    handler._automation_events = StanceRequestHandler._automation_events.__get__(handler)

    return handler


class TestAutomationConfigEndpoint:
    """Tests for /api/automation/config endpoint."""

    def test_config_returns_dict(self, handler):
        """Test that config returns a dictionary."""
        result = handler._automation_config(None)
        assert isinstance(result, dict)

    def test_config_structure(self, handler):
        """Test config structure."""
        result = handler._automation_config(None)
        assert "notify_on_scan_complete" in result
        assert "notify_on_scan_failure" in result
        assert "notify_on_new_findings" in result
        assert "notify_on_critical" in result
        assert "min_severity_for_new" in result
        assert "critical_threshold" in result
        assert "trend_threshold_percent" in result

    def test_config_values(self, handler):
        """Test config default values."""
        result = handler._automation_config(None)
        assert result["notify_on_scan_complete"] is True
        assert result["notify_on_critical"] is True
        assert result["min_severity_for_new"] == "high"


class TestAutomationTypesEndpoint:
    """Tests for /api/automation/types endpoint."""

    def test_types_returns_list(self, handler):
        """Test that types returns a list."""
        result = handler._automation_types(None)
        assert "types" in result
        assert "total" in result
        assert isinstance(result["types"], list)

    def test_types_structure(self, handler):
        """Test type structure."""
        result = handler._automation_types(None)
        assert result["total"] == 7

        ntype = result["types"][0]
        assert "value" in ntype
        assert "description" in ntype
        assert "trigger" in ntype

    def test_types_includes_expected(self, handler):
        """Test that expected types are included."""
        result = handler._automation_types(None)
        values = {t["value"] for t in result["types"]}
        assert "scan_complete" in values
        assert "scan_failed" in values
        assert "critical_finding" in values
        assert "trend_alert" in values


class TestAutomationHistoryEndpoint:
    """Tests for /api/automation/history endpoint."""

    def test_history_returns_list(self, handler):
        """Test that history returns a list."""
        result = handler._automation_history(None)
        assert "history" in result
        assert "total" in result
        assert isinstance(result["history"], list)

    def test_history_structure(self, handler):
        """Test history entry structure."""
        result = handler._automation_history(None)
        assert len(result["history"]) > 0

        entry = result["history"][0]
        assert "notification_type" in entry
        assert "timestamp" in entry
        assert "scan_id" in entry
        assert "message" in entry

    def test_history_filter_by_type(self, handler):
        """Test filtering history by type."""
        result = handler._automation_history({"type": ["scan_complete"]})
        assert all(h["notification_type"] == "scan_complete" for h in result["history"])

    def test_history_limit(self, handler):
        """Test limiting history results."""
        result = handler._automation_history({"limit": ["2"]})
        assert len(result["history"]) <= 2


class TestAutomationThresholdsEndpoint:
    """Tests for /api/automation/thresholds endpoint."""

    def test_thresholds_returns_list(self, handler):
        """Test that thresholds returns a list."""
        result = handler._automation_thresholds(None)
        assert "thresholds" in result
        assert "total" in result
        assert isinstance(result["thresholds"], list)

    def test_thresholds_structure(self, handler):
        """Test threshold structure."""
        result = handler._automation_thresholds(None)
        assert result["total"] == 3

        threshold = result["thresholds"][0]
        assert "name" in threshold
        assert "value" in threshold
        assert "description" in threshold
        assert "affects" in threshold


class TestAutomationTriggersEndpoint:
    """Tests for /api/automation/triggers endpoint."""

    def test_triggers_returns_list(self, handler):
        """Test that triggers returns a list."""
        result = handler._automation_triggers(None)
        assert "triggers" in result
        assert "total" in result
        assert isinstance(result["triggers"], list)

    def test_triggers_structure(self, handler):
        """Test trigger structure."""
        result = handler._automation_triggers(None)
        assert result["total"] == 6

        trigger = result["triggers"][0]
        assert "name" in trigger
        assert "event" in trigger
        assert "enabled" in trigger
        assert "description" in trigger

    def test_triggers_includes_expected(self, handler):
        """Test that expected triggers are included."""
        result = handler._automation_triggers(None)
        events = {t["event"] for t in result["triggers"]}
        assert "scan_complete" in events
        assert "scan_failed" in events
        assert "critical_finding" in events


class TestAutomationCallbacksEndpoint:
    """Tests for /api/automation/callbacks endpoint."""

    def test_callbacks_returns_list(self, handler):
        """Test that callbacks returns a list."""
        result = handler._automation_callbacks(None)
        assert "callbacks" in result
        assert "total" in result
        assert isinstance(result["callbacks"], list)

    def test_callbacks_structure(self, handler):
        """Test callback structure."""
        result = handler._automation_callbacks(None)
        assert result["total"] == 3

        callback = result["callbacks"][0]
        assert "name" in callback
        assert "type" in callback
        assert "description" in callback


class TestAutomationSeveritiesEndpoint:
    """Tests for /api/automation/severities endpoint."""

    def test_severities_returns_list(self, handler):
        """Test that severities returns a list."""
        result = handler._automation_severities(None)
        assert "severities" in result
        assert "total" in result
        assert isinstance(result["severities"], list)

    def test_severities_structure(self, handler):
        """Test severity structure."""
        result = handler._automation_severities(None)
        assert result["total"] == 5

        severity = result["severities"][0]
        assert "value" in severity
        assert "priority" in severity
        assert "description" in severity

    def test_severities_includes_all_levels(self, handler):
        """Test that all severity levels are included."""
        result = handler._automation_severities(None)
        values = {s["value"] for s in result["severities"]}
        assert "critical" in values
        assert "high" in values
        assert "medium" in values
        assert "low" in values
        assert "info" in values


class TestAutomationStatusEndpoint:
    """Tests for /api/automation/status endpoint."""

    def test_status_returns_dict(self, handler):
        """Test that status returns a dictionary."""
        result = handler._automation_status(None)
        assert isinstance(result, dict)

    def test_status_structure(self, handler):
        """Test status structure."""
        result = handler._automation_status(None)
        assert "module" in result
        assert "version" in result
        assert "status" in result
        assert "components" in result
        assert "capabilities" in result

    def test_status_operational(self, handler):
        """Test status is operational."""
        result = handler._automation_status(None)
        assert result["status"] == "operational"

    def test_status_components(self, handler):
        """Test status includes required components."""
        result = handler._automation_status(None)
        components = result["components"]
        assert "NotificationHandler" in components
        assert "NotificationConfig" in components


class TestAutomationTestEndpoint:
    """Tests for /api/automation/test endpoint."""

    def test_test_returns_dict(self, handler):
        """Test that test returns a dictionary."""
        result = handler._automation_test(None)
        assert isinstance(result, dict)

    def test_test_structure(self, handler):
        """Test test result structure."""
        result = handler._automation_test(None)
        assert "test_type" in result
        assert "would_trigger" in result
        assert "notification" in result
        assert "matching_triggers" in result

    def test_test_default_type(self, handler):
        """Test default notification type is scan_complete."""
        result = handler._automation_test(None)
        assert result["test_type"] == "scan_complete"

    def test_test_critical_finding(self, handler):
        """Test critical_finding notification type."""
        result = handler._automation_test({"type": ["critical_finding"]})
        assert result["test_type"] == "critical_finding"
        assert result["would_trigger"] is True

    def test_test_scan_failed(self, handler):
        """Test scan_failed notification type."""
        result = handler._automation_test({"type": ["scan_failed"]})
        assert result["test_type"] == "scan_failed"


class TestAutomationSummaryEndpoint:
    """Tests for /api/automation/summary endpoint."""

    def test_summary_returns_dict(self, handler):
        """Test that summary returns a dictionary."""
        result = handler._automation_summary(None)
        assert isinstance(result, dict)

    def test_summary_structure(self, handler):
        """Test summary structure."""
        result = handler._automation_summary(None)
        assert "config" in result
        assert "stats" in result

    def test_summary_config_section(self, handler):
        """Test config section in summary."""
        result = handler._automation_summary(None)
        config = result["config"]
        assert "triggers_enabled" in config
        assert "callbacks_count" in config

    def test_summary_stats_section(self, handler):
        """Test stats section in summary."""
        result = handler._automation_summary(None)
        stats = result["stats"]
        assert "notifications_sent_24h" in stats
        assert "scan_completions_24h" in stats
        assert "critical_alerts_24h" in stats
        assert "by_type" in stats


class TestAutomationWorkflowsEndpoint:
    """Tests for /api/automation/workflows endpoint."""

    def test_workflows_returns_list(self, handler):
        """Test that workflows returns a list."""
        result = handler._automation_workflows(None)
        assert "workflows" in result
        assert "total" in result
        assert isinstance(result["workflows"], list)

    def test_workflows_structure(self, handler):
        """Test workflow structure."""
        result = handler._automation_workflows(None)
        assert result["total"] == 4

        workflow = result["workflows"][0]
        assert "name" in workflow
        assert "trigger" in workflow
        assert "actions" in workflow
        assert "enabled" in workflow
        assert "description" in workflow

    def test_workflows_actions_are_lists(self, handler):
        """Test that workflow actions are lists."""
        result = handler._automation_workflows(None)
        for workflow in result["workflows"]:
            assert isinstance(workflow["actions"], list)


class TestAutomationEventsEndpoint:
    """Tests for /api/automation/events endpoint."""

    def test_events_returns_list(self, handler):
        """Test that events returns a list."""
        result = handler._automation_events(None)
        assert "events" in result
        assert "total" in result
        assert isinstance(result["events"], list)

    def test_events_structure(self, handler):
        """Test event structure."""
        result = handler._automation_events(None)
        assert result["total"] == 6

        event = result["events"][0]
        assert "name" in event
        assert "source" in event
        assert "description" in event
        assert "data_fields" in event

    def test_events_data_fields_are_lists(self, handler):
        """Test that event data_fields are lists."""
        result = handler._automation_events(None)
        for event in result["events"]:
            assert isinstance(event["data_fields"], list)


class TestAutomationEndpointRouting:
    """Tests for automation endpoint routing in do_GET."""

    def test_get_endpoints_exist(self):
        """Test that all automation GET endpoints are routed."""
        endpoints = [
            "/api/automation/config",
            "/api/automation/types",
            "/api/automation/history",
            "/api/automation/thresholds",
            "/api/automation/triggers",
            "/api/automation/callbacks",
            "/api/automation/severities",
            "/api/automation/status",
            "/api/automation/test",
            "/api/automation/summary",
            "/api/automation/workflows",
            "/api/automation/events",
        ]

        for endpoint in endpoints:
            method_name = "_automation_" + endpoint.split("/")[-1]
            assert hasattr(StanceRequestHandler, method_name), f"Method {method_name} not found"
